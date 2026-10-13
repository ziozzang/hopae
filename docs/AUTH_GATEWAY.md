# Service authentication gateway

<!-- doc-rev: 5 -->

[Documentation](README.md) · [한국어](ko/AUTH_GATEWAY.md) · [Native integration](HANGANG_NATIVE.md)

Runtime connectors authenticate local service API keys or relay a Bearer credential
to a fixed external verifier, with optional IP conditions. It is opt-in through `authentication_gateway`; existing OIDC/session
routes keep their behavior when this configuration is absent. The same caller
key, bounded concurrency and forwarded-request validation apply before API
credentials are read, over both HTTP and HOP1.

```json
{"authentication_gateway":{"authority_id":"example","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"HOPAE_ORDERS_API_KEY","subject":"scheduler"}],"networks":["192.0.2.0/24"],"session_fallback":false}]}}
```

Each profile must match a configured application's ID, exact host and ports.
Scopes cannot overlap. The referenced credential must contain 32–1024 printable
ASCII bytes; use a generated secret. Only the environment reference is public
configuration. Startup checks reject unavailable/invalid/duplicate credentials.
Optional key `expires_at` is an absolute Unix millisecond timestamp. Observed
expiration cannot be reversed by a wall-clock rollback within the process;
persisted cross-restart expiration watermarks remain future work.

The runtime keeps SHA-256 credential indexes and compiled IPv4/IPv6 prefix trees
in memory, with bounded profiles, credentials and network nodes. Queries do not
access SQLite, call providers or store credentials. This version is file-owned
and compiled at startup: changing references, expiry or networks requires
restart. Database-owned publication, rotation APIs, management UI and distributed
invalidation remain implementation work.

A profile selects a presented Bearer credential. Missing credentials are denied
unless `session_fallback:true` explicitly permits the existing session engine.
Invalid, duplicate, malformed, expired or network-disallowed credentials never
fall back to a browser session. Network conditions use the authenticated
forwarded client address, not a new caller-supplied identity claim. Reserved
login/logout paths retain their existing session behavior.

Successful authentication emits an opaque `s_…` subject derived from principal
kind, authority/issuer, realm and configured subject. It emits
`x-hopae-principal-kind: service`, `x-hopae-aal: 0` and the authenticated
`x-hopae-service-id`; it does not invent a human
account, verified email or MFA. Replies contain no credential and use
`Cache-Control: no-store`. Authentication is not a service permission grant:
Hangang/Pumgye enforce the service matrix. Hangang validates the service kind,
AAL 0 and exact authenticated service audience, requires an enforced Pumgye
gate, and consumes the incoming Authorization credential before policy/transforms
and upstream dispatch. A role must explicitly allow AAL 0; an API key cannot
satisfy a human/MFA requirement.

`tools/service_stack_smoke.py` runs three actual isolated processes over mTLS
HOP1/PPG1. It verifies authentication, IP/class/method rights, unknown/invalid
credential denial, durable permission revocation/restoration without rewriting
gateway configuration, cross-service isolation, credential consumption and
Pumgye-outage fail-closed. Guard is outside this fixture; it is not a full-stack
throughput measurement. Operational rollout and full credential lifecycle,
including existing-stream credential revocation, remain separate work.

LDAP, local human passwords, standard introspection adapters, Any/All composition
with actual connector relationships, upstream credential translation, full
credential lifecycle and full-stack 100k QPS qualification remain open. Existing OIDC circuits protect provider network calls; external verifier relays
also use scoped circuits, while the in-memory API-key connector has no remote
backend to circuit-break.

## External API verifier relay

A profile may configure `api_relay` instead of `api_keys` (the two are mutually
exclusive). Set a fixed `url`, trusted `issuer` namespace, optional
`verifier_key_env` and `timeout_ms` (1–1000, default 100). HTTPS is required
except explicitly enabled loopback fixtures. Private destinations require
`allow_private_endpoints:true`; redirects, URL credentials/queries/fragments
and environment proxies are refused, and public DNS answers are vetted at
connection time. The configured issuer/realm defines identity; the response
cannot choose another issuer or claim human assurance.

The connector POSTs JSON `{service_id, client_ip}` and sends the original
credential as a sensitive Bearer Authorization header. The optional verifier
credential uses the sensitive `x-hopae-verifier-key` header. The URL never
comes from a request. The verifier returns JSON with only `active`, `subject`,
`service_id` and `expires_at` fields. Active responses require an exact service
match, a bounded subject and an absolute Unix millisecond expiry after receipt
within five seconds. Evidence lasts at most one second; network time is included
in expiry validation. False assurance/extra fields, wrong audiences and expired
responses are refused. Replies use the existing service namespace and AAL 0,
then Pumgye independently enforces permissions.

Each connector allows at most 64 exchanges and shares persistent HTTP
connections. Requests have the configured total deadline and a 64 KiB response
cap. Credential denials remain 401; backend/contract errors, saturation and
timeouts become 503 without session fallback. Three consecutive backend or
semantic failures open a process-local circuit for 30 seconds, with a single
recovery probe; cancellation releases its probe. Ordinary credential denial
does not trip the circuit. No result cache, upstream credential exchange,
persisted quarantine, management publication or RFC 7662 field adapter is
implemented by this first verifier contract.

## Composed evidence lease

The `compose_verified` core contract now preserves the validated subject and service
audience and caps freshness at the earliest supplied evidence expiry or one second,
whichever comes first. Any/All still reject unknown or duplicate connectors, expired
evidence, conflicting namespaced subjects and mismatched audiences. The resulting
read-only evidence contains no assurance-level claim; multiple service/network
factors do not imply human MFA. Tests verify audience retention, earliest expiry,
the one-second cap and expiry rejection. This is a composition primitive; runtime
connector orchestration and explicitly verified cross-provider subject relationships
remain pending. Existing request profiles still select their configured connector.

## Human second factors and extension contract — implementation backlog

Operator requirements include native TOTP compatible with Google Authenticator,
external authentication API calls and extensible adapters, potentially Lua. These
are required work, not implemented MFA merely because `FactorKind::Totp` and AAL 2
exist in the model. Service API evidence stays AAL 0; network evidence alone does
not become a human possession factor.

The proposed factor engine is separate from first-factor provider adapters. A
challenge binds the internal user ID, primary provider evidence, session/transaction,
service audience, browser binding, requested assurance, policy revision, expiry and
single-use nonce. Successful factor verification returns typed evidence to the core;
only the core combines independent factors, commits challenge consumption and OTP
replay state, rotates credential generation/handles and issues assurance. Changes to
identity, provider, policy, enrollment or session state invalidate pending challenges.
No cached successful OTP result can authorize another challenge.

Native enrollment creates a random per-user seed encrypted under a versioned key
outside the database. Enrollment is pending until a valid code proves possession;
provisioning material is shown once over the authenticated portal and never exported
through the Hangang broker or audit. Start with 30-second, six-digit HMAC-SHA-1 TOTP
and a bounded adjacent-step window; qualify actual authenticator interoperability.
Persist the last accepted counter with atomic compare-and-set across replicas;
clock rollback cannot restore an accepted code. Limit attempts per account/challenge
and network; serialize successful consumption under the DB authority. Enrollment,
replacement and removal require recent authentication and appropriate step-up;
recovery codes are individually hashed, single-use and auditable, and recovery must
not silently inherit unrestricted MFA assurance. Revocation closes or downgrades
sessions and streams according to service policy. OTP is not phishing-resistant.

External factor APIs must use fixed operator-approved HTTPS endpoints and identities,
no redirects/environment proxy or request-selected URLs, bounded request/response,
deadline/concurrency and a circuit breaker. Requests bind nonce, user, audience and
operation; replies must bind those same fields with short expiry and an authenticated
provider result. A plain `success=true` cannot grant MFA. Denial differs from provider
unavailability; required-factor outages fail closed without bypass or key fallback.
Provider provenance and allowed factor capabilities prevent a password or IP check
from claiming an independent possession factor.

A Lua adapter would receive only capability-scoped context and opaque secret handles,
with instruction, memory and wall-time limits, restricted libraries and approved
host-mediated network calls. Script publication requires validation, revision CAS,
audit and rollback. Scripts cannot mint sessions, write arbitrary DB state, choose
assurance levels or disclose raw credentials. Native TOTP remains in Rust; Lua is
an optional extension mechanism and must be qualified independently.

Required qualification covers algorithm vectors, enrollment/rotation/recovery,
concurrent replay across processes, clock rollback, challenge swaps, revoked factors,
external API substitution/outage/circuit recovery, sandbox escape/resource exhaustion,
service step-up and Hangang console/stream propagation. Internal dogfooding is required.
Algorithm references: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). Protocol parameters and lifecycle
above are proposed Hopae choices; the RFCs do not define this enrollment/API design.

## TOTP arithmetic source status

`src/factor/totp.rs` implements HMAC-SHA-1/256/512 dynamic truncation, six/eight
ASCII digits, fixed 30-second steps and at most one adjacent step on either side.
Seeds are bounded to 20–128 bytes, redact Debug and zeroize their owned bytes on drop.
Expected OTP and HMAC buffers are zeroized; submitted values use the existing Secret
wrapper. All window candidates are compared with constant-time byte equality.
Negative time and malformed codes are refused. The result is only a matching counter,
filtered against a caller-supplied last-accepted watermark; it carries no user binding,
factor provenance or assurance and cannot create a session by itself.

Two focused tests cover all 18 RFC 6238 Appendix B vectors, large timestamps,
leading zeros, six-digit defaults, malformed input, bounded window and watermark
refusal including rollback. Actual authenticator enrollment is not qualified.
No enrollment endpoint, seed encryption at rest, recovery, durable concurrent replay
CAS, MFA session/console integration or external factor/Lua adapter is implemented
by this arithmetic change. Those lifecycle requirements remain mandatory before
claiming TOTP authentication support.
