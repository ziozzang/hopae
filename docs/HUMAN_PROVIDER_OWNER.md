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
