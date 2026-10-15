# Native TOTP establishing-factor prerequisite

[한국어](ko/HUMAN_TOTP_PROVENANCE.md)

Schema migration 8 adds internal `session_totp_provenance`, with one row per
session. Only the real native TOTP elevation transaction records its establishing
enrollment ID/revision, user/session/new credential generation, original factor
index/time, and optional configuration generation. It stores no seed, code,
envelope, cookie, raw proof or OTP counter. Successful native elevation commits
this association with proof/challenge consumption, credential rotation and audit;
any failure rolls them back together. Replacement requires a strictly higher
credential generation for the same user. Session deletion cascades the row.

Migration does not backfill existing AAL2 sessions from current enrollments or old
factor labels. Existing native flows with no configuration generation still work
and record an explicitly unqualified association. Ordinary verify behavior is
unchanged; the additive internal owner checker refuses missing provenance or
missing/current-mismatched configuration generation.

The crate-private checker requires the exact establishing entry in the session
factor list, current session generation/user state, and the exact still-active
owned enrollment revision. Another session may legitimately advance the same
enrollment's counter: this does not retire the earlier session's factor owner.
Factor revocation/session termination, changed enrollment/provenance/configuration,
missing rows, store failure/deadline and a different opened Store refuse. A read
never refreshes the original factor timestamp, session touch or freshness budget.
Read-only foundation validation refuses a missing/weakened schema without repair.

This is provenance infrastructure, not a Human authentication capability, observed
clock proof or complete current-session owner. No public RPC or additional grant
is provided. Later native Engine Allow must bind exact HandleView/native snapshot
and current provider/session/user/factor/application owners and original admission
and emission fences. This work does not add self-owned password accounts, Google
forced reauthentication, recovery, remote directory withdrawal or arbitrary SQL
rollback/live clone protection.
