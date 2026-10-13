# LDAP authentication provider

<!-- doc-rev: 28 -->

[Documentation](README.md) · [한국어](ko/LDAP_AUTHENTICATION.md)

## Status and integration point

Proposed implementation contract, not an enabled provider. The current Provider
trait models OAuth authorization redirects and callbacks, and Registry instantiates
OIDC only. LDAP must use a credential submission adapter into the same transaction,
identity resolution, session, handoff, reauthentication and revocation services.
It must not emulate an OAuth callback or forward passwords through HOP1/API relay.
Add an explicit direct-credential provider interface alongside the redirect interface;
the chooser can display both without requiring LDAP to implement OAuth code exchange.

## Authentication flow

The browser selects a configured provider and submits username/password only to
Hopae's HTTPS portal. Validate the transaction, browser binding, CSRF and return
scope first. Reject empty username/password before any directory operation. Apply
existing per-IP/account throttling, a bounded connector semaphore and one total
lookup/TLS/bind deadline. Never retain, log, return or queue password material for
asynchronous retry. Directory outages are unavailable, not invalid credentials,
and cannot fall back to another provider without a new explicit login choice.

A read-only directory identity performs a bounded subtree search with escaped
filter values, fixed base DN and configured attributes. Require exactly one entry;
zero matches, multiple matches and referrals cannot authenticate. Read an immutable
configured identity attribute such as entryUUID or objectGUID for the namespaced
subject; do not use the mutable DN, username or email as the permanent principal.
DN renames preserve identity and a recreated username with a different immutable
identifier does not inherit the former user's permissions.

Verify the password by binding as the found DN on a separate TLS connection. Never
reuse a user-bound connection across users or return it to the lookup pool. A failed
bind, cancellation or protocol error destroys that connection. Successful lookup
alone is not authentication. Require confidential authenticated TLS before either
service credentials or user credentials are sent: explicit CA/name verification,
no certificate bypass and no downgrade from required StartTLS to plaintext. StartTLS
and LDAPS may be separate explicit configured modes, never opportunistic fallback.

## Identity, session and mixed providers

Successful bind produces a Human identity in the configured directory namespace
with AAL 1 and a local authentication timestamp. It creates the ordinary Hopae
session/handoff through the existing transaction service. LDAP does not claim an
OIDC provider auth_time or MFA. Fresh reauthentication requires a new password bind;
a cached search result or existing Hopae session cannot satisfy it. Email claims
are non-authoritative by default. Account linking to OIDC/local/API identities
requires a separate verified relationship and cannot be inferred from matching email.

Pumgye owns service permissions; LDAP groups are evidence and require explicit
mapping, not automatic administrator grants. Hopae combines providers, while
Hangang continues to enforce service audience and rights using native transport.
Directory-disabled/deleted identities must revoke local sessions according to a
bounded reconciliation lease. Polling interval, webhook availability and unreachable
directory behavior must be explicit; implementation cannot promise immediate remote
revocation without a directory change feed. Password changes require an independently
verified lifecycle signal or periodic session revalidation.

## Configuration and release gates

Configuration contains endpoint, TLS mode and CA/server name, base DN, immutable
subject attribute, escaped username filter template, service-bind secret references,
attribute allowlist, time/result limits and revocation lease. Hopae owns their DB
publication; delegated administrators cannot introduce undeclared secret references
or arbitrary private endpoints. Directory secrets never enter console responses.

Before enabling kind=ldap, qualify the complete chooser/form/session/handoff flow
against an owned OpenLDAP server with generated CA. Test empty passwords, bad name
and missing trust roots, plaintext downgrade, invalid credentials, duplicate search
results, referrals, filter/DN metacharacters, cancellation, cross-user connection
reuse, username recreation, disabled accounts, password change, service permission
absence, cross-provider linking and circuit-open recovery. Run actual Hangang/Hopae
requests and qualify concurrent latency separately from local directory throughput.
No production directory is assumed to be available for this qualification.

## References

- [OpenLDAP security considerations](https://www.openldap.org/doc/admin26/security.html): empty-password simple bind can be unauthenticated access.
- [OpenLDAP TLS configuration](https://www.openldap.org/doc/admin26/tls.html): certificate verification and TLS modes.
- [RFC 4513](https://datatracker.ietf.org/doc/html/rfc4513): LDAP authentication and TLS security mechanisms.

## Implemented interface foundation

`provider::credentials::CredentialProvider` now defines bounded direct password
verification separately from OAuth begin/callback and returns the existing
ProviderIdentity shape for future session integration. PasswordInput borrows a
Secret, has no serialization/clone implementation and redacts both username and
password in Debug. Its constructor rejects empty credentials, control characters
in usernames and oversized input without trimming password material. Typed failures
distinguish invalid credentials, unavailable provider and disabled provider. This
interface does not yet implement LDAP TLS/search/bind, local password hashing,
portal form handling or session issuance; its identity/assurance requirements remain
connector and portal implementation contracts until those paths are qualified.

## Implemented directory connector

`provider::ldap::LdapProvider` implements the direct credential interface using
ldap3 with rustls. It requires LDAPS or explicit mandatory StartTLS, absolute
bounded regular-file CA material and verified endpoint certificates; credentials
are environment references. A 64-operation semaphore and 1–2000 ms total deadline
cover lookup, service bind, streaming search and independent user bind. The fixed
attribute filter escapes username values, requires one result and a single bounded
text immutable identity attribute, and rejects referrals. Every connection driver
is aborted on scope exit/cancellation; user-bound connections are never pooled.
Parser conversion panics are converted to unavailable, and responses cannot supply
email authority or provider auth_time. Binary objectGUID support, hard BER frame
bounds and persistent service-lookup pooling still require implementation/review.

An owned OpenLDAP fixture validates successful TLS bind, repeatable entryUUID,
rejection of invalid credentials, absent users, duplicate users, injected filters
and an incorrect CA.
It generates ephemeral credentials and certificates and removes its container.
Reproduce with `docker build -t hopae/owned-openldap:bookworm tests/fixtures/ldap`
then `python3 tools/owned_ldap_smoke.py`. The fixture runs the explicitly ignored
connector integration test; ordinary unit tests do not require Docker. This qualifies
the connector slice, not the portal chooser/form, session issuance, revocation,
circuit lifecycle, complete performance or an operational LDAP provider deployment.

## Connector circuit

LDAP now uses the same shared monotonic, generation-bound admission lease as the
API verifier relay. Three consecutive backend failures open the circuit for 30
seconds; recovery permits one half-open probe. Cancellation records a failure via
lease drop. Invalid user credentials and missing/ambiguous user results remain
healthy directory responses, while TLS/connect/search failures, service-bind errors
and malformed results are unavailable. Semaphore saturation rejects immediately
without treating capacity pressure as directory failure. The owned OpenLDAP test
checks ordinary credential denial leaves the circuit closed and three wrong-CA
failures open it. Circuits remain process-local; provider registry publication,
persistent quarantine and administrative recovery are not implemented by this slice.

## Mandatory StartTLS qualification

The owned directory fixture now runs the credential scenarios over both LDAPS
and explicitly required StartTLS. An additional owned rejecting peer observes
StartTLS as the first protocol operation, returns an unavailable ExtendedResponse
and verifies connection closure without a subsequent bind. Rejection cannot fall
back to cleartext authentication. Certificate and invalid-user/circuit tests run
for both configured modes. These tests do not activate LDAP in the portal registry
or establish session revocation and high-load performance guarantees.

## Immutable subject encoding

The connector supports explicit subject_encoding values text (default) and
binary_hex. Subjects include a lowercased attribute namespace and encoding prefix:
`t:entryuuid:<value>` or `b:objectguid:<raw-byte-hex>`. Binary bytes are encoded
without GUID endianness reinterpretation. Text/binary values and different attribute
names cannot collide. Require one case-insensitive attribute occurrence and one
value. Text is bounded to 128 bytes with no controls; binary to 64 bytes. Missing,
ambiguous and excessive values fail closed. Binary encoding preserves original
bytes even when ldap3 exposes valid UTF-8 data through its text attribute map.

Unit tests verify ambiguity and encoding isolation. Real owned OpenLDAP returns a
non-UTF-8 binary attribute and its exact encoding is checked over both TLS modes.
This does not certify Active Directory compatibility or user lifecycle. No operational
LDAP identities existed before this prototype subject format change.

## Provider storage preparation

Migration 0004 adds the distinct ldap provider kind while preserving existing
provider data in one transaction. Foundation validation rejects claimed v4 state
without the new kind. LDAP uses a password factor and does not imply MFA.
Configuration and registry activation remain disabled until chooser, transaction
and session wiring is complete. This schema is not deployed internally.

Tests preserve provider ownership and secret references, verify idempotence and
force failure after table replacement to prove restoration of the original table
and migration version. Existing user/session/admin migration checks pass. Older
schema-v3 binaries cannot open v4 databases: future rollback requires a consistent
pre-migration database backup, not just restoring the previous image.

## Direct authentication result boundary

The authenticate_password wrapper now validates direct connector results and fixes
principal kind to Human, AAL to 1, and authentication time provenance to
HopaeCompletion. It records local completion time, rejects provider auth_time and
verified/authoritative email claims, checks subject/claim bounds, and rechecks
provider identity, kind and enabled state after the bounded verification call.
A connector cannot supply an MFA assertion through this result shape. Credential
failures preserve their typed distinction; invalid results are unavailable.

Tests cover forged provider time and disable during verification, plus real LDAP
results through this wrapper over LDAPS and StartTLS. This prepares session input;
it does not create sessions, implement portal CSRF/transactions, or replace the
required provider-enabled fence inside the eventual session creation transaction.

## Raw claim containment

Direct password results now require an empty JSON object for raw_claims. Arbitrary
metadata, credential echoes and assurance assertions are rejected before the verified
session-input object is constructed. Future directory attributes need a separate
typed allowlist rather than inheriting the OIDC raw-claim container. Tests reject
credential-bearing objects, AAL assertions, null and array results, and confirm the
real LDAP connector still passes through both TLS modes. Portal/session issuance
remains unimplemented; this is the result-boundary contract, not a full login flow.

## Configuration and credential registry preparation

ProviderEntry now carries a typed ldap configuration, preserved through policy
snapshots and database import without password values. OIDC client_id remains
required for OIDC; LDAP rejects OIDC credentials and implicit account linking.
The known-key tree recognizes the LDAP fields and environment warnings identify
missing bind references without reading disabled providers' credentials.

Registry maintains direct credential providers separately from redirect providers.
Stored enabled LDAP rows compile the TLS connector; malformed or disabled/deleted
rows remain addressable as disabled credential providers. The owned OpenLDAP test
looks up an LDAP provider through this registry and authenticates its stable subject
over both TLS modes. LDAP reauthentication capabilities remain Unsupported/None,
even if its ID matches an OIDC preset or stored config claims max_age. The CLI's
LDAP portal activation gate remains: selector/form/transaction/session integration
and operational deployment are still required.

## Shared session completion preparation

The session service now separates provider authentication from its common identity,
session and handoff completion stage. Existing OIDC callbacks use this private
stage after state/binding checks, provider verification and freshness validation.
The stage preserves identity conflict handling, single-use transaction consumption,
provider fences, reauthentication and handoff issuance. Direct credential callers
still need their own authenticated transaction binding and portal route; this
refactor alone does not create a LDAP login endpoint.

All-target gates passed on the final source, including 413 library tests, 365
scenario cases and the existing OIDC callback/disable-race checks. The explicitly
ignored LDAP fixture and 40 scenario cases remain separate qualification work.
An obsolete successful-upgrade assertion was updated to the current schema version;
malformed v3 databases still retain version 3 and are refused before migration.

## Direct transaction binding storage

TransactionBinding now preserves optional nonce and PKCE values rather than storing
empty OAuth placeholders. A direct login challenge can retain its single-use digest,
provider and immutable portal binding while storing NULL in the OAuth-only columns.
Existing redirect authentication preserves its actual nonce/verifier values.
A storage test verifies absent OAuth fields and rejects browser-binding replacement.
Library and OIDC callback regressions pass. This is storage preparation; the portal
still needs explicit direct challenge creation, CSRF validation and password completion
before LDAP activation. No new operational schema upgrade is needed for these already
nullable columns, and no LDAP login endpoint is enabled by this change.

## Session-service direct challenge preparation

ProviderLookup now exposes credential providers separately from redirects. The
session service's begin_password loads a live login transaction, checks browser
cookie shape and IP binding, rejects existing binding, validates the selected
provider's database kind/enabled/tombstone state and enforces own-provider
reauthentication. It creates a random challenge digest with NULL OAuth fields and
an immutable portal binding. Preparation never invokes password verification.
Known direct providers are retained in refusal diagnostics without credentials.

An owned real-store scenario verifies missing-cookie and disabled-provider rejection,
no binding on rejection, successful challenge lookup, absent OAuth fields and
second-bind conflict. Library and native regressions pass. Portal CSRF/form routing
and credential completion/session issuance still need connection before activation.

## Direct credential session completion

The session service now completes a password challenge without an OAuth callback.
It checks challenge shape, single-use status, expiry, purpose, provider identity,
absent OAuth fields, portal/app binding and client IP before credential verification.
It validates the direct result, rechecks live provider kind/configuration afterward,
and uses common identity/session/handoff completion with AAL 1 and local time.
Invalid credentials are a typed invalid_credentials failure; no session is created
and the challenge can be retried under the portal's required throttling policy.

An owned real-store test connector covers invalid credential retry, successful
session/handoff issuance, local authentication provenance, AAL 1, replay rejection
without another backend call, and provider disable during verification without a
second session. These are service-level tests with a controlled connector, not a
full real-LDAP browser login. Existing library/native regressions and Clippy pass.
Portal form/CSRF/throttling wiring, configured-connector epoch fencing, remote LDAP
revocation and operational activation remain required.

## Browser mismatch before verification

The direct-completion store scenario now presents a valid challenge from a different
portal cookie. It verifies refusal consumes that challenge without invoking the
credential connector or creating another session. Existing invalid-credential retry,
success, replay and provider-disable cases remain in the same scenario. Clippy passes.
This verifies the service binding boundary; HTTP CSRF and password-form integration
remain separate work before operational activation.

## Password form template preparation

The portal PasswordForm template is now available in English and Korean. It uses
POST to the provider password path with hidden challenge and CSRF fields, labeled
username/current-password inputs and generic refusal text. The model has no field
for a password value, so a retry cannot prefill or echo it. Provider labels are
HTML-escaped under the existing script-free template policy. Rendering tests cover
both locales, labels, POST binding and absence of a password value attribute.
This template is not yet connected to a HTTP route or provider chooser; CSRF,
throttling, credential submission and operational LDAP activation remain pending.

## Portal credential adapter

PortalServices now accepts a borrowed PasswordSubmission independently of the
OAuth callback interface. Adapter validates PasswordInput, calls the direct session
completion method and returns the existing handoff/handle response; failure preserves
typed unavailable versus credential rejection. PasswordSubmission has no Debug or
serialization implementation. Its contract requires HTTP origin/CSRF and attempt
throttling before invocation. The real-store service scenario now exercises this
adapter and verifies a handoff response. Portal tests and Clippy pass. HTTP route,
HTTPS enforcement, CSRF/throttle handler and chooser wiring are not enabled yet.

## Password HTTP endpoint and attempt admission

POST `/login/{provider}/password` now prepares trusted request context, requires
HTTPS and the existing Login Origin/CSRF guard, rejects duplicate/missing credential
fields and applies bounded password admission before calling PortalServices.password.
It accepts bounded form data only and emits the existing handoff response or generic
failure. The password field is never put in a URL or response by the handler.

Admission permits ten CSRF-valid submissions per canonical IP per monotonic minute,
with at most 4096 IP windows. IPv4-mapped IPv6 cannot obtain a second quota. Active
windows are not evicted on saturation; expired windows release capacity, and poison
fails closed. Excess attempts return 429 with Retry-After 60. This state is process-local,
not persistent or shared across replicas; per-account and cluster-wide controls remain
required before broad deployment. The ordinary session-verification path does not
use this limiter.

Real-router tests with a controlled service verify plaintext, missing Origin and
ambiguous fields are refused without a credential call; only ten submissions reach
the service. Portal tests pass (61 cases). The chooser and initial password form are
still not wired, LDAP configuration activation remains gated, and this endpoint is
not yet deployed internally. End-to-end real-directory/browser qualification remains.

## Initial password form dispatch

PortalServices.prepare_password and the adapter now prepare a real session-service
challenge and return provider label plus redacted Secret metadata. The existing
provider selection POST dispatches a registered credential provider to this path,
requires HTTPS after its Origin/CSRF check, and renders PasswordForm with a newly
issued Login CSRF token. Redirect-provider handling remains on begin_provider.
The real-store adapter scenario uses this preparation before credential completion;
a real-router controlled-service test confirms selection renders the bound form
without invoking credential verification. Portal 62 cases and Clippy pass.

The direct providers still need inclusion in initial/reauthentication chooser lists
and single-provider redirect handling, and configuration activation remains gated.
This is source integration, not an internal LDAP deployment or complete real-directory
browser qualification. Distributed/account admission and connector epoch fencing
also remain required.

## Mixed-provider chooser integration

Session ProviderLookup now exposes enabled credential providers separately. Normal
and reauthentication chooser construction merges them with redirect providers,
checks live directory rows and kind, preserves stored display names/order and avoids
duplicate IDs. A direct-provider reauthentication offers its own live provider only.
The portal adapter treats a configured direct connector as available for form dispatch
and excludes it from the single-provider OAuth auto-redirect shortcut. Selection
therefore uses the bound password form instead of trying an OAuth authorization URL.

The real-store direct-provider scenario verifies its chooser entry and display name.
Library tests (419), OIDC scenarios (36) and strict Clippy passed. Configuration still
refuses LDAP activation pending real browser/directory qualification, connector epoch
fencing, hard directory response bounds and revocation work. This chooser integration
has not been deployed to the internal environment yet.

## Concurrent password admission qualification

A 32-thread synchronized test mixes native IPv4 and IPv4-mapped IPv6 submissions
and verifies exactly one shared ten-attempt IP budget. A poisoned-state test proves
admission fails closed rather than panicking or reopening the quota. Capacity,
expiry and monotonic-window tests also pass. This is an admission invariant check,
not a distributed quota implementation or full-stack throughput benchmark.

## Configuration freshness before credential submission

Direct password completion compares the live database LDAP configuration with the
connector's compiled typed configuration before submitting credentials. A mismatch
fails closed without calling the backend. Typed parsing includes default values;
endpoint, TLS mode, CA path, bind-secret reference, directory attributes and timeout
must match. The existing post-authentication database comparison remains in place.

The real-store scenario verifies that changing configuration prevents even a correct
password from reaching the connector. Owned LDAPS and StartTLS tests verify connector
configuration matching; focused tests and strict Clippy pass. This does not fingerprint
CA file contents or resolved secret values, fence the final database commit against a
concurrent configuration change, or qualify LDAP production activation.

## New-session write fence

Direct LDAP/password completion now carries the verified provider kind and database
configuration into session creation. The SQLite write transaction requires an existing,
enabled, non-tombstoned provider with the same kind and parsed JSON configuration
before inserting a session, handle or login event. A store regression verifies refusal
with no writes on stale configuration and successful creation for matching state.

This closes the last-read race for new-session creation. Identity resolution remains
a separate transaction; configuration fencing of session reuse and reauthentication,
actual secret/CA rotations and hard BER frame limits remain outstanding. LDAP remains
unavailable through production configuration pending those activation requirements.

## Existing-session reuse fence

The direct-login session-reuse branch also passes the expected provider kind and
configuration into transaction consumption. The same SQLite write fence refuses stale
configuration before consuming the login challenge or recording events. A store test
checks that refusal preserves the unconsumed challenge and audit state, then permits
matching configuration. Reauthentication still needs equivalent fencing before its
handle rotation; the production activation gate remains closed.

## Reauthentication write fence

Direct-provider reauthentication carries the verified kind/configuration into the
same write transaction that consumes the login challenge, rotates handles and increments
credential generation. The transaction checks provider liveness and expected configuration
before those mutations. Store regressions reject both a changed kind and stale configuration
without changing authentication time, generation, handles, challenge or success audit.
The existing successful rotation test remains in place.

New-session creation, existing-session reuse and reauthentication now share transactional
configuration fencing. Identity creation is still a separate transaction. This comparison
does not detect same-reference secret/CA content rotations or an ABA configuration change;
persistent epochs and LDAP response bounds/browser/revocation qualification remain open.

Validation: all-target gates pass with `RUST_TEST_THREADS=1` (423 library,
15 other integration and 366 scenario cases; 1 owned LDAP and 40 scenarios ignored).
Earlier parallel runs each failed one pre-existing load-sensitive test: SQLite query
interruption instrumentation and the 200-request overload burst. Both passed alone;
the complete serial run passed, preserving concurrency inside each scenario.
This is not evidence that parallel test stability or full-stack performance is solved.
The existing allowed dependency warning remains.

## Bounded LDAP wire frames

Hopae pins a locally vendored ldap3 0.12.1 with a pre-parser outer BER frame
check. Definite-length LDAP sequences are capped at 64 KiB including the header.
An oversized declared length is refused as soon as its header arrives, before
lber parsing or waiting for the body. Indefinite lengths and invalid outer tags
are refused. Fragmented allowed frames and multiple coalesced frames are retained.
Patch provenance, upstream licenses and maintenance instructions are in
[vendor/ldap3/HOPAE_PATCH.md](../vendor/ldap3/HOPAE_PATCH.md).

Two focused wire tests and owned LDAPS/StartTLS authentication pass with the patched
library. The cap bounds each wire frame, not parser recursion, total connection memory,
all malformed nested BER, or aggregate results. Nested-parser hardening and actual
malicious TLS peer qualification remain necessary before production activation.

## Nested BER preflight and malicious TLS qualification

The vendored decoder now scans each complete frame iteratively before lber parsing,
using a fixed 32-context stack and a 4096-element limit. It rejects truncated tags or
lengths, indefinite nested lengths, excessive tag/length widths and children outside
their parent. Primitive payload bytes are skipped rather than interpreted as children;
only the first complete frame is scanned when several arrive together.

Three focused structure tests pass. Owned certificate-verified TLS peers send an
oversized header without its body and a deeply nested complete frame, keep their
connections open, and observe client closure within one second. The LDAP connector
reports unavailable within that bound. Both cases pass during LDAPS and StartTLS
fixture runs. Existing real-directory identity, invalid credentials and circuit tests
also pass. These bounds do not qualify all LDAP semantic/control parsing, aggregate
memory, directory revocation or actual browser/gateway activation.

## Credential response semantics and aggregate bounds

The vendored LDAP codec now validates response shapes before upstream infallible
conversion paths: message arity/classes/IDs, nonnegative bounded integers,
result fields and UTF-8, referrals, entry attribute/value shapes (binary values
remain supported) and control wrappers including Boolean length. Unsupported
credential operations are refused. The AD extended-response outer-OID workaround
is retained after validation. Dispatch binds each single response to its request
operation, so a success ExtendedResponse cannot authenticate a Bind request.
Unexpected search response kinds become connection errors rather than panics.

Credential searches are limited to eight response frames before enqueueing,
independently of a server-side size-limit hint. At the existing 64 KiB frame cap
this bounds queued search wire payload to 512 KiB per operation; parsed object
and other connection overhead are additional. The connector's concurrency and
whole-operation deadline remain in force. This fork is credential-only: generic
intermediate/sync operations, opaque control-value parsers and GSSAPI/SASL paths
are not enabled/qualified by these changes.

Six focused vendored tests cover framing, semantic rejection without panics,
valid results/binary entries/referrals/controls/AD notice and deterministic wire
mutations passed through downstream result/entry parsing. The owned TLS fixture
passes real LDAPS and mandatory StartTLS authentication plus malicious peers
that send empty/missing-result/invalid-control frames, a search entry or wrong
success-result kind during Bind, a Bind response during Search, or nine valid
search entries while withholding completion. These peers keep the connection
open; client closure and unavailable classification must occur within one second.
The runtime configuration barrier remains: actual LDAP browser/session/revocation
and distributed lifecycle qualification are still required before activation.
