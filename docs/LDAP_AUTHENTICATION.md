# LDAP authentication provider

<!-- doc-rev: 8 -->

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
