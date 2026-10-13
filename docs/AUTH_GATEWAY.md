# Service authentication gateway

<!-- doc-rev: 18 -->

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

## Seed envelope source status

`src/factor/seed_cipher.rs` adds XChaCha20-Poly1305 envelopes with a fresh 24-byte
nonce from the existing production CSPRNG, a versioned external 32-byte key, and
length-delimited associated data binding the purpose, key ID, internal user and
enrollment ID. Envelope fields are private; bounded JSON parsing rejects documents
over 1024 bytes, unsupported versions and invalid ciphertext lengths. Key and
plaintext buffers use zeroizing ownership and Debug redacts key/envelope contents.
No plaintext seed or key is serialized. All decryption failures use one typed error.

Focused tests check round trips, cross-user/enrollment/key substitution, ciphertext,
nonce and version tampering, fresh nonces and bounded identifiers/input. This module
is not connected to the database or enrollment UI yet. Production key loading,
keyring rotation/backup/retirement, pending enrollment, replay CAS, recovery and
session integration remain required. It does not prevent replay of a valid older
ciphertext; the owner database must enforce enrollment revision and revocation.
Cipher API reference: [RustCrypto chacha20poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/).

## TOTP owner storage source status

Schema v5 stores encrypted enrollment envelopes, pending/active/revoked state,
revision, last counter and pending expiry. Unique indexes allow one pending and one
active enrollment per user. The Factors store creates pending state for an active
user with ten-minute expiry. Activation requires owner/revision, unexpired pending
state and an active user, then advances revision and records the verified counter.
Consumption requires the expected revision, active owner/enrollment and a strictly
larger counter. Revocation advances revision. Caller-supplied events commit with
mutations; refusals do not record success events.

The SQLite regression covers owner mismatch, replay/lower counter, revision and
revocation, and same-counter races through two independent writer connections.
This is not multi-process/fleet qualification. Counters must already be verified by
the trusted caller. Atomic challenge/session completion, typed factor audit events,
read/enrollment services, expired-pending cleanup, replacement, recovery and UI remain
unfinished; no HTTP handler invokes these primitives. Source schema v5 is not deployed
internally. Rollback requires consistent prior-schema backup restoration because old
binaries cannot open an upgraded database.

## Internal enrollment read and lifecycle qualification

The Factors boundary now reads an encrypted enrollment by exact owner and ID.
It returns only active or unexpired pending state for an active user; revoked,
expired, wrong-owner and disabled-user state is unavailable. The internal row is
not serializable and its envelope Debug is redacted; it must never be returned by
the console broker. The authentication service still needs to decrypt using the
configured keyring and recheck lifecycle revision at its final write.

A SQLite lifecycle regression verifies pending read/decryption, exact expiry refusal,
revocation of expired pending state, rollback of activation when required event
insertion fails, persisted active revision/counter through an independent reopen,
and disabled-user read/consumption refusal while revocation remains possible.
The rollback test uses a synthetic existing required event to force a duplicate-ID
failure; it does not implement factor-specific audit semantics. Full process restart,
challenge/session atomicity, pending cleanup/replacement, enrollment/recovery UI,
key management and internal MFA dogfooding remain required.

## Native verification and owner consumption

`src/factor/service.rs` connects owner-bound encrypted enrollment lookup, key
verification/decryption and the fixed native six-digit/30-second TOTP profile to
revision-fenced database mutation. Enrollment confirmation refuses already-active
state; authentication consumption refuses pending state. The enrollment confirmation
counter is consumed at activation, so it cannot immediately authorize authentication.
Revocation, owner disable or competing counter consumption after lookup is refused
by the final write. The non-serializable receipt records purpose, owner, enrollment,
resulting revision/counter and verification time; it confers no AAL or session authority.

The real-store regression confirms enrollment once and admits exactly one of two
concurrent verifications of a subsequent valid code. This internal service is not an
HTTP route: admission, recent authentication, challenge binding, atomic challenge/session
completion, keyring selection, factor-specific audit, recovery/UI and internal dogfooding
remain required. Counter consumption alone must not be followed by a separate unsafe
session elevation transaction; integrated completion still needs one atomic write.

## Internal v3-to-v5 migration and backup rollback qualification

The actual internal Hopae schema-v3 database was copied with SQLite's backup API
into a private qualification directory. The offline candidate was opened by the
current Store implementation and migrated to v5. Integrity checks and aggregate
content comparisons verified preservation of all 13 existing business tables.
Restoring the consistent backup reproduced schema v3 and the original table contents.
All copies, including the upgraded candidate, use the backup API: copying only the
main file can omit WAL-resident migrations and give a false rollback result.

The currently deployed `0.0.2-profile-console-9b307c0` image was run in isolated
containers without network or live-state mounts. Its `admin list` command opened
the restored v3 database and refused a verified v5 candidate as too new. Private
credentials and CLI output were kept outside public evidence. Production state was
not migrated. This proves offline data migration and old-image CLI compatibility,
not complete application boot, provider/login qualification or deployment readiness.

Reproduce with `cargo build --example qualify_owner_migration` and
`python3 tools/qualify_owner_migration.py --database <owner-db> --output <new-private-directory> --qualifier target/debug/examples/qualify_owner_migration`.
The Rust helper accepts only an existing `migration-candidate.db`; the Python runner
never migrates its input. The candidate and backups contain private identity/session
material and must remain private. Operational rollout still needs a candidate image,
full boot/regression checks and migration-aware rollback before internal activation.

## Internal owner-v5 deployment and dogfooding — 2026-10-13

The static Linux-musl binary from source `d876909` was packaged as
`hopae:0.0.2-owner-v5-d876909`. A parallel loopback-only candidate booted against a
consistent private copy of the actual owner state at schema v5. HTTP and persistent
mTLS HOP1 accepted the existing service key and refused missing/invalid credentials.

Operational deployment stopped the prior instance, took a consistent schema-v3 backup,
changed only the image selection and restarted the instance. Schema v5 and health
were verified. Actual Hangang HTTPS service rights/denial/credential consumption,
unified Hopae/Sumunjang/Pumgye menus and matrix, SSO entry, logout, anonymous/origin
isolation and native mTLS regressions passed. Configuration and existing provider
selection remained unchanged. Private prior-schema backups and migration-aware rollback
are retained; public evidence contains no credentials or identity/session rows.

This deploys the latest source primitives and API-profile circuit continuity, not
active LDAP login or OTP enrollment/step-up. Their production configuration/UI remain
unfinished. A real external human SSO login, directory revocation, upstream credential
translation, factor challenge/session atomicity, distributed followers/membership,
full-stack throughput and public multi-platform releases remain open. Internal
service/console dogfooding continues; the complete zero-trust gateway goal is active.

## Enrollment preparation source status

`src/factor/enrollment.rs` generates a fresh 20-byte seed with the existing CSPRNG,
constructs a Google Authenticator-style `otpauth` URI for SHA1/six digits/30 seconds,
encrypts it with owner/enrollment binding and commits pending state before returning
provisioning material. Issuer/account labels are bounded, reject colons/controls and
are percent-encoded; issuer prefix and query issuer match. Base32 omits padding.
The URI wrapper is non-serializable, non-cloneable, zeroizing and Debug-redacted;
explicit exposure is for the future authenticated enrollment response only. There
is no API for recovering provisioning material from an existing stored seed.

Three focused tests check URI fields/encoding, invalid labels and real-store pending
commit before disclosure; duplicate preparation fails without replacing the existing
row or returning another URI. This does not guarantee one-time browser display:
recent authentication, CSRF/Origin, no-store/referrer/CSP response controls, QR rendering,
confirmation/recovery/removal UI, admission, keyring loading and challenge/session
atomicity remain required. No registration route is enabled. The historical upstream
[Google key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
is the encoding reference; a current real-app scan has not been qualified.

## Expired pending replacement and required factor audit

Creating a fresh pending enrollment now revokes an expired pending enrollment for
the same active user in the same transaction as insertion. A live pending enrollment
still prevents duplicate preparation. Failure of insertion or caller-required audit
rolls back both cleanup and new enrollment. Cleanup permanently advances the old
revision and tombstones its state; clock rollback cannot revive that cleaned row.
It does not replace an existing active factor or provide an enrollment HTTP route.

The store emits required `factor.enrollment_prepared`, `factor.enrollment_activated`,
`factor.enrollment_expired`, `factor.totp_consumed` and `factor.enrollment_revoked`
events even when the trusted caller supplies no events. Each contains only owner and
enrollment identifiers with a store correlation marker, and travels through the same
transactional outbox. No seed, URI, code, counter or key is added to event attributes.
Factor events describe storage mutations; consumed-counter audit alone does not
prove a challenge-bound MFA session or identify an HTTP actor.

A real-store regression checks live-pending refusal, expired replacement, rollback
on duplicate required event, and six lifecycle events with their pending outbox rows.
Recent-authentication/actor correlation, atomic active-factor replacement,
challenge/session completion, recovery/UI and internal MFA dogfooding remain open.

## Operator-reference keyring source status

`src/factor/keyring.rs` compiles one active encryption key and up to sixteen
explicit retained decryption keys into immutable memory. Configuration contains
only IDs and environment references. The entire reference set is validated before
secret resolution: bounded IDs, conventional environment names, unique IDs/references
and an existing active ID. Each referenced value must decode from exactly 43
unpadded Base64url characters into 32 bytes. Zero keys, missing/malformed material
and duplicate actual key material are refused. Loaded strings/decoded buffers are
zeroizing; the compiled keyring Debug is redacted.

Encryption uses only the active key; envelope decryption selects the exact retained
key ID with no active-key, environment or network fallback. Two tests qualify active
key changes with retained old decryption, retirement refusal and malformed/duplicate
references/material. This is a configuration loading component, not an enabled root
configuration setting or HTTP/admin key-management endpoint. Keyring loading into
application startup, safe revisioned rotation/rewrapping, external key storage,
backup/retirement policy, enrollment HTTP flow and internal MFA qualification remain
unfinished. Operators must generate high-entropy keys; structural validation does
not prove entropy. Retiring a referenced key before rewrapping disables its factors.

## Keyring integration into factor services

Enrollment preparation now accepts the compiled keyring and encrypts only with its
active key. Native TOTP verification performs one owner-state lookup and selects the
exact retained key named by that envelope before decryption. Missing/retired keys
produce uniform refusal before counter or enrollment mutation; no caller-selected
single key, active-key retry, environment lookup or network fetch is used during
verification. The keyring remains immutable for the duration of the service call.

Real-store tests qualify retained-key verification after an active-key change,
retirement refusal with unchanged pending state, enrollment preparation and concurrent
single-use verification. Root configuration/startup loading, policy publication fencing
for key retirement, envelope rewrapping, enrollment/step-up HTTP/UI and atomic
challenge/session completion remain unfinished. Source changes are not in the current
internal `owner-v5-d876909` image. Key rotation tests do not constitute deployed
operator key-management or complete MFA lifecycle support.

## Startup keyring wiring

Root `totp_keyring` now validates reference shape and material in preflight. Application
binding compiles and retains an immutable Arc keyring before acquiring the instance
lock, opening/migrating the database or binding listeners. Invalid material fails with
one redacted error. With no setting, existing startup and provider behavior is retained.
A config regression covers known-key parsing/reference validation/redacted material
errors, and a bind regression verifies missing material creates no state directory.

This is bootstrap wiring, not complete factor HTTP support. Runtime key publication/
retirement fencing, rewrapping, recent authentication, admission, enrollment/step-up UI,
challenge/session atomicity and internal MFA dogfooding remain required. The deployed
internal `owner-v5-d876909` image predates this setting and is not configured with it.

## Schema-v5 foundation checks

Startup/CLI foundation validation now requires the TOTP owner table, lifecycle and
ciphertext columns, STRICT mode, and both unique partial per-user indexes. It checks
index uniqueness, partial status, exact owner column and pending/active predicate;
matching an index name alone is insufficient. An invalid structure returns a redacted
schema-v5 corruption error through the existing read-only precheck before backup or
migration. This does not validate every table constraint or row's cryptographic content.

A regression migrates fresh in-memory databases and damages the table, counter column,
index presence, uniqueness, owner column or predicate. Every damaged case is refused;
normal v5 passes. Full application/recovery qualification, factor HTTP/UI, atomic
challenge/session completion and internal rollout of these later changes remain open.

## Native owner authorization for enrollment preparation

The session service can issue a non-serializable, redacted FactorActor after validating
the portal handle's user/lifetime/binding, AAL 1 or above, authentication no older than
five minutes, current user authorization version and live provider row. It contains
no raw cookie and grants a five-second write lease. The authorized preparation service
derives the seed owner from this actor; the caller cannot supply a different user.

The pending-enrollment transaction rechecks lease time (including rollback), exact
session/handle/host, credential generation, authentication time, authorization version,
active user/provider, non-revoked handle/session, AAL and absolute/idle lifetime.
An existing active factor refuses initial enrollment; replacement needs its own
step-up flow. Provisioning material is returned only after this fenced commit.
The older unfenced storage/preparation primitives remain trusted internal/operator
APIs and must not be used by end-user HTTP handlers.

A real-store regression constructs an internal actor and tests normal preparation
against twelve post-read changes including revocation, generation/version changes,
provider deletion, stale authentication/lifetime, lease expiry and an active factor.
The test covers the write fence, not browser actor issuance or transport. HTTPS,
CSRF/Origin, bounded admission, request/audit correlation, confirmation/removal fencing,
key-retirement publication and atomic challenge/session completion still need their
HTTP/service integration. No enrollment route or MFA session elevation is enabled.
