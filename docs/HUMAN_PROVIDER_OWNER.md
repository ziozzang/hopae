# Durable provider incarnation prerequisite

[한국어](ko/HUMAN_PROVIDER_OWNER.md)

The internal SQLite provider-owner boundary prepares future native Human session
capture. It does not issue Human receipts, expose an RPC, prove a user login or
complete the Human owner contract. Existing Service, Workload and ordinary native
session behavior remain separate. Native password forms authenticate LDAP; this
work does not add self-owned password accounts or Google forced reauthentication.

Schema migration 7 initializes each existing provider's positive incarnation and
retains a sidecar tombstone after deletion. SQLite triggers advance incarnation
in the same transaction on insertion, deletion, or changes to kind, enabled/deleted
state, serialized config, secret reference, domain/link/trust policy. Deleting and
recreating an ID or restoring old configuration never reuses the previous
incarnation. Provider IDs cannot be renamed in place; use explicit deletion and
creation. Integer overflow aborts the owning mutation rather than wrapping.

Display name, sorting, management attribution and timestamps do not change this
owner. An identical file import remains stable. Serialized JSON changes may
conservatively invalidate even if their meaning is equivalent. No migration
rewrites existing providers, sessions, factors or grants.

The crate-private reference has no numeric constructor, serialization, or Debug
implementation. Capture and recheck perform bounded current reads joining the
live provider to its incarnation; missing, disabled or deleted providers refuse.
A reference also belongs to one opened Store instance, so another Store or a
reopened Store cannot accept it. No cookie, provider configuration or secret is
retained in the reference. One SELECT establishes a database read linearization
point; it is not a lock against subsequent revocation.

Later Human integration must bind this infrastructure to actual native verification,
exact session/handle/user/factor provenance and current configuration owners, with
original BOOTTIME admission and final emission fences. This reference alone grants
no Human or MFA authority. It does not poll remote LDAP/OIDC account state, detect
arbitrary database backup rollback, or fence independently cloned live processes.
Migration/backup and source-process retirement remain separate requirements.

## Actual compiled Registry preparation

The production startup now prepares the actual durable provider rows and their
incarnations in one bounded SQLite read transaction, after the existing config
generation/import writes. The generation must already exist and match; no default
is invented. At most4096 rows are prepared. The same rows configure native OIDC
and LDAP adapters and their private owner map retained inside the Registry.
File-only settings do not replace retained/API-managed DB authority.

The exact application snapshot is frozen once and its same ArcSwap is reused by
Services. Registry retains that original Arc and its owning publisher. An owner
requires the actual compiled adapter to be enabled/usable: missing credentials,
invalid LDAP trust/config, unsupported kinds or absent adapters never qualify
merely because the DB row enabled bit is set. Ordinary public from_snapshot
registries remain usable for their existing role but have no additive owner map.

Publication rechecks the durable owner set/generation and application identity
before returning Bound, after fallible bind/listener preparation. OIDC refreshers
are deferred until this check succeeds. A later fallible run/router build can
still fail; existing Weak refreshers may finish a bounded in-flight fetch before
stopping. No universal “failed startup made no external request” claim is made.

A private provider fence belongs to that Registry and Store. Current checks use
the original prepared incarnation/config generation, not a late binding to new
DB rows. Disable/re-enable, material ABA, deletion/recreation or application Arc
replacement refuse; an observed failed check retires that fence. A newer prepared
Registry is required to use a changed provider. Runtime Registry is currently
fixed at startup and configuration reload requires restart. Unobserved privileged
ArcSwap rollback, arbitrary DB restore and live clones are not solved here.

These are fresh durable-read correctness checks, not a completed authentication
hot path or Human grant. Later source-backed immutable memory snapshots and
membership/publication gates must preserve owner retirement without exporting
numeric capabilities; their cache/follower/performance qualification remains
open. Actual Engine session/factor/app binding and Human protocol are still queued.
