# Authentication profile publication

<!-- doc-rev: 12 -->

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

A console publication writes `admin.profiles_publish` (`revision`, `status`
`enabled` or `disabled`, the optional `reason` as `note`, the actor) inside the
publication's own transaction, so a refused or conflicting publication records
nothing ([administration](ADMIN.md#audit-events)).

## Dry-run validation

`POST /v1/authentication/profiles/validate` with `{"configuration": …}` runs
the checks a publication would run and publishes nothing. It answers `200` with
`{"valid": bool, "errors": [{"path", "code", "message"}]}`; `path` points into
the posted configuration (`profiles[0].ports[1]`, `""` for the whole
document). Codes, in the order the checks run:

| Code | Meaning |
| --- | --- |
| `invalid_document` | The shape is wrong (unknown field, wrong type, missing field); only the first mismatch is reported |
| `undeclared_reference` | An API key variable, or a relay with a verifier key, a CA file or private endpoints, that the configuration file does not declare |
| `invalid_profile` | A profile breaks the runtime rules (identifiers, bounds, connectors, networks) |
| `configuration_rule` | A rule of the whole configuration, such as a profile that matches no application host and port |
| `invalid_configuration` | A rule no single profile explains (duplicates across profiles) |
| `compile_failed` | The profiles could not be compiled, for example a referenced variable is absent from the environment |

`null` (disable the gateway) is always valid. Any grant may validate; the
request follows the console's JSON API rule, is rate-limited per actor (30,
refilling one every two seconds) and writes `admin.read` (purpose
`profiles.validate`, the body's digest and the number of findings) before the
answer. Messages never contain a secret value.

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

## Internal deployment qualification

The static Linux build and console package 0.1.3 are deployed internally. A real
Hangang console browser loaded the durable reference-only profile, published the
identical configuration through the signed broker, observed revision increment,
and verified logout cleanup and anonymous denial. Gateway configuration revision
and authentication settings stayed unchanged. Live service authentication, role
matrix, mTLS native transports, unified module menus and existing SSO regressions
passed. Consistent database backup, package pins and previous-image rollback are
kept private. All-target checks passed: 400 library, 15 other integration and 365
scenario tests; 40 scenarios remain explicitly ignored. Audit retains its existing
unmaintained PEM-parser warning. This is an internal feature deployment, not a
new public multi-platform release or complete lifecycle/throughput qualification.

## Publication continuity

Unchanged service/realm verifier bindings retain their connector across publication,
including transport pools, capacity permits and circuit state. Binding fingerprints
cover the complete connector configuration and a digest of resolved verifier
credential material; changed secrets or security options do not reuse the connector.
A real loopback verifier test opens the circuit, changes the network profile and
proves the next authentication is suppressed without another outbound request.
The authority also shares its observed time floor across snapshots and disabled
periods, so observed credential expiry cannot be undone by publication and a clock
rollback. This floor is process-local, not a persistent restart watermark. Removed
and subsequently recreated connectors and process replacement still need durable
circuit/quarantine lifecycle work. These changes are source-qualified; the currently
deployed internal binary predates this continuity fix.


## Configuration-authoritative mode

`authentication.source` decides who owns the authentication profiles
(`authentication_gateway`) and the credential projection plan
(`credential_projection`):

| `authentication.source` | Owner | Start | Console and API edits |
| --- | --- | --- | --- |
| `store` (default) | The store | The file bootstraps an empty store only; a stored document (or tombstone) wins over a changed file | Allowed (`PUT /v1/authentication/profiles`, `/projections`) |
| `config` | The file | Every start reconciles the store to the file | Refused: `409 config_authoritative` |

In `config` mode a start first validates and compiles the file's profiles with
the same checks as a publication. An invalid file stops the start with a clear
error and leaves the store untouched. When the stored document differs from the
file, the start publishes the file through the CAS publication: next revision,
an audit row with actor `config`, a disabled tombstone when the file has none,
and the required event `authentication.reconciled` (`attrs.kind` =
`profiles` or `projections`, `previous_revision`, `revision`, `actor`). An
equal document keeps its revision and writes nothing. For the projection
plan, the plans are compared and the file's plans are published at the
store's next revision (the file's own `revision` is ignored in this mode).
`GET /v1/authentication/profiles` reports `source`.

This is the declarative mode a Kubernetes package needs: Helm values change the
file and the store follows — without a restart (below).

### Live reconciliation

In `config` mode Hopae also polls the configuration file while it runs
(`authentication.reload_interval_ms`, default 1000; `0` turns it off, so only
a start reconciles). Polling compares the file's content digest; it uses no
file-system notifications, because a ConfigMap volume replaces a symlink
(`..data`) that inotify watches on the file miss. A changed file goes through
everything a start does — size bound, parse, validation of the whole
configuration, the referenced environment variables, compilation of the
profiles — and only then is the store reconciled through the same CAS
publication (next revision, audit row with actor `config`) and the live
snapshot swapped. The record is `authentication.reconciled` with
`attrs.cause = reload`. A revoked API key or a removed profile stops
authenticating on the next request after the swap.

| The changed file | Effect |
| --- | --- |
| Valid, profiles or projection plans differ | Reconciled live: new revision, record, `hopae_config_reloads_total{result="reconciled"}` |
| Valid, equal profiles and plans | Nothing written |
| Invalid (unparsable, an invalid profile, a missing variable, …) | Nothing changes: the current profiles stay in force; `hopae_config_reload_failing` = `1`, a warning, and `GET /v1/status` → `reload.config.failing` and `error` until a valid file arrives |
| Other keys changed (listeners, providers, `authentication.source`, …) | Not applied: `reload.config.restart_required = true`, `result="restart_required"`, a warning; the next start applies them |
| Profiles appear where Hopae started without any | Reported as invalid: starting the authentication gateway needs a restart |

**Timing.** With the default 1 s poll, a revocation is in force within about
one second of the file changing inside the container (the poll interval plus
validation and one store transaction). How fast the file changes after the
ConfigMap object is updated is outside Hopae: the kubelet refreshes ConfigMap
volumes on its sync period plus its cache TTL (by default up to about a
minute), and never for `subPath` mounts. When revocations must be faster,
mount the ConfigMap as a whole directory (not `subPath`) and either lower the
kubelet's `configMapAndSecretChangeDetectionStrategy`/sync period, use a
projected volume fed by a sidecar that writes the file directly (for example
a config-reloader that watches the API), or deliver revocations through the
console in `store` mode. Hopae's part of the latency is bounded by
`authentication.reload_interval_ms`.

Migration:

- **store → config:** copy the current document (`GET
  /v1/authentication/profiles`, and `/projections`) into the file, set
  `authentication.source = "config"`, and restart. An equal document keeps
  its revision; any difference is published at the next revision and
  recorded.
- **config → store:** set `authentication.source = "store"` (or remove it)
  and restart. The store keeps the last reconciled document, and console
  edits work again. Later file changes no longer apply: the file only
  bootstraps an empty store.
