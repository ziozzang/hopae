# Authentication profile publication

<!-- doc-rev: 8 -->

[Documentation](README.md) · [한국어](ko/AUTH_PROFILE_PUBLICATION.md)

## Status and ownership

This is a proposed implementation contract. Current authentication profiles are
file-owned and compiled at startup. Hopae owns the future profile database,
credential references, publication audit and compiled runtime. Hangang delegates
administration through its existing authenticated console lease; Pumgye continues
to own permissions. Neither gateway callers nor classifiers may publish profiles.

## Durable model

Store one authority document with revision, canonical document digest and schema
version, plus append-only publication audit in Hopae's own SQLite transaction.
The document contains environment references, never bearer material. A deletion
is a persisted empty/disabled authority, not a missing row: restarting must never
restore removed profiles from the bootstrap file. File import happens only before
an authority row exists. Changing authority/realm/issuer namespaces requires an
explicit identity migration; publication must not silently inherit old grants.

## Publication and request execution

A bounded blocking worker serializes publications under the existing exclusive
instance ownership. Validate document size, application scope and connector bounds,
resolve allowed secret references, and compile the complete candidate before writing.
The mutation requires administrator authorization, existing CSRF/origin checks,
and an exact revision precondition. Viewer and data-plane credentials cannot mutate.

Commit the document, next revision, digest and audit together, then atomically swap
an ArcSwap runtime containing that revision. Do not await between commit and swap.
Cancellation of the HTTP caller must not cancel the worker. A post-commit inability
to install the snapshot fences authentication readiness until recovery; it cannot
continue answering with a known stale allow. Startup loads and compiles the durable
row before becoming ready; missing references or corrupt state fail closed.

Each request loads one immutable runtime snapshot. No profile database query or
lock is allowed in the authentication hot path. Reply evidence carries the authority
revision and bounded freshness. Successful publication also advances the revocation
generation consumed by Hangang streams and pools. Profile/key removal must invalidate
open streams within the declared one-second evidence bound; request-only rejection
is insufficient. An unchanged verifier connector may retain its circuit across a
publication only when endpoint, issuer, secret reference and security options match.

## Interface and verification gates

Proposed delegated GET/PUT `/v1/authentication/profiles` returns revision, digest
and reference-only configuration. PUT uses If-Match; stale concurrent writes return
409, invalid candidates 422, unavailable durable storage 503. The authenticated
actor and outcome are audited without credentials or verifier response bodies.

Before activation, test durable deletion across restart, malformed/oversized bodies,
missing secret references, viewer/data-plane denial, concurrent CAS, cancellation
before and after commit, persistence failure, failed snapshot installation, and
open-stream revocation. Exercise actual Hopae/Hangang processes and preserve old
provider sessions. DB-backed distributed followers require separate signed/revisioned
snapshot leases and are not implemented by this single-owner publication contract.

## Implemented storage primitive

`auth_gateway::publication` now stores a revisioned reference-only document and
append-only audit keys in Hopae's existing `meta` table in one immediate SQLite
transaction. It validates bounded configuration, verifies the document digest on
read, rejects stale revisions and preserves a disabled tombstone across reopen.
An audit collision rolls the authority update back. This primitive does not yet
connect the startup loader, management API, compiled runtime swap or stream
revocation; those activation gates remain required. Production callers must compile
and authorize before publishing, and install or fence the runtime after commit.

The `auth_gateway::authority` worker primitive now compiles before persistence and
installs the revisioned runtime with ArcSwap immediately after commit. Its shared
reader handle avoids database locking. Startup prefers durable state, including
a disabled tombstone, over bootstrap configuration; a failed scope check or missing
secret leaves durable state unchanged. Request/admin wiring and stream-generation
enforcement remain pending; existing snapshot holders intentionally retain the old
snapshot until their caller enforces its lifetime.

GatewayState can now receive the shared authority reader. Each HTTP/HOP1 verify
loads one runtime snapshot, and a presented bearer credential whose profile was
removed is denied rather than falling back to a human cookie. The native parity
scenario publishes a tombstone while retaining the connection and verifies the
next request is denied. Production startup and delegated administration still use
the existing file-owned path until their explicit wiring is completed; this does
not yet revoke an already-open upstream application stream.

The application startup now initializes an authority from its existing utility
connection when profiles or durable state exist, validates application scope, and
shares its reader with the gateway router. The actual three-process fixture verifies
a disabled durable authority survives Hopae replacement with its bootstrap file
unchanged. The first stale pooled connection may return 503; subsequent reconnects
return 401. The fixture installs the tombstone as an owned offline database operator;
it does not prove a delegated management API, which remains unimplemented. Older
file-oriented CLI/preflight semantics still require separate migration review before
removing obsolete bootstrap secret references in an operational deployment.

GET `/v1/authentication/profiles` is now registered behind the existing admin
authentication/delegation gate. It returns the durable reference-only document,
revision ETag and no-store, or revision 0 when no authority exists. Four dedicated
blocking worker permits remain held until each database read finishes even if the
HTTP deadline expires. The authenticated scenario checks anonymous rejection and
inspection of an owned persisted profile. PUT remains pending: it must recheck the
actor inside the write transaction using the existing administrator fence. The
Hangang plugin UI and deployment of this endpoint are not yet qualified.

PUT `/v1/authentication/profiles` now requires a singular quoted If-Match revision
and a body containing only the required `configuration` field (null disables).
The listener applies CSRF and administrator-role checks for this PUT. Its bounded
blocking worker recompiles the candidate, invokes the existing actor fence inside
the immediate transaction and again before commit, then installs the snapshot
without an intervening await. Caller cancellation does not cancel that worker.
Bootstrap-declared secret references are the current allowlist; verifier credentials
and private endpoints additionally require the original endpoint/issuer/security
binding. Declaring new references therefore still needs operator configuration.
Tests cover viewer/CSRF denial, undeclared private endpoint denial, stale revision,
durable tombstone and precommit actor denial rolling back both state and audit.
The Hangang delegation middleware still restricts its endpoint allowlist, so this
new write path is currently the authenticated native Hopae admin API; integrated
console write controls and deployment remain pending. No stream revocation or
complete authentication-lifecycle claim follows from these request-level checks.

The delegation adapter now accepts GET profile inspection and signed POST
`/v1/authentication/profiles/publish` with required `revision` and `configuration`.
After verifying the original body digest and nonce it constructs the internal PUT
body and If-Match from those authenticated fields, then applies the normal admin
gate and transactional actor fence. Replay and stale revision scenarios pass.
Hopae console package 0.1.3 adds the profile tab and reference-only JSON editor,
using the loaded revision for save and disabling viewer writes. An owned browser
component fixture checks rendering, submitted revision/configuration, viewer denial
and abort cleanup with a mocked host API. Actual deployed broker/UI publication
qualification and stream revocation remain pending.
