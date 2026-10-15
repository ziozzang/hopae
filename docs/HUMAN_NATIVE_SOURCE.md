# Native Human source records (implementation candidate)

This additive source accepts the actual private native Engine `Checked` and a validated fixed `human_request::Binding`. It does not accept an identity, realm, signature-only proof or numeric lifetime as a capability. The native configured signing key signs kind Human=1, qualified native AAL1 or TOTP AAL2, actual user authorization revision and post-elevation session credential generation. `human1` comes from the durable native user/realm and fixed configured issuer. Service and Workload receipt paths are unchanged.

The source binds one exact native Owner and immutable current publication. A new publication requires a new source and retirement of the old source; incoming generation values cannot update it. Original Admission, same Owner BOOTTIME clock generation, native current Store/provider/material/session/user/factor/app checks and readiness remain mandatory. Signed expiry and every admission report intersect the original age; ObserveTime cannot renew it. A valid signature without the exact local retained record refuses, including an independent empty source instance. Records are affine process evidence until distributed authority fencing is implemented. Human receipt RPC activation remains explicit and default-off. This module does not establish complete Human/Root/Pum chain qualification.

`receipt_issuer.human_receipts` is optional and absent by default. Its fixed configuration includes `source_revision`, `capacity`, `retained_bytes`, and scopes with service/audience/application/route, route revision, lowercase 64-hex destination digest, header revision, fixed header/reserved-header names and maximum entity bytes. Scopes must belong to the configured issuer's declared service/audiences; no Service authentication profile is required. The request remains metadata-only (the SDK hashes the actual body, up to the existing 16 MiB limit); the native receipt RPC remains bounded to 128 KiB.

Count defaults to 131,072, configurable through 1,048,576. Requested retained capacity defaults to 256 MiB, configurable through 16 GiB with checked native-size conversion. **Both bounds apply:** byte capacity may exhaust well before count capacity; the count does not promise that many records fit or qualify throughput. The quota charges record-owned allocation capacities, fixed context capacity reservation, and fixed prepared-scope/publication lease metadata once. It excludes the existing immutable application/provider/DB/transport baseline and allocator fragmentation/overhead; it is not an RSS limit. No full configuration graph is multiplied by record count. Native Checked excludes raw cookie reconstruction and per-record AppPolicy duplication.

The source uses 256 short-lock shards. Both each shard's record index and expiry heap have at most `2 * ceil(capacity / 256)` entries: at the maximum configuration, 2,097,152 record-index entries and 2,097,152 expiry entries are independently bounded across all shards. Opaque HashMap/heap allocation baseline is separate from the record byte quota. Normal admission cleans at most eight expired heads from one shard; pressure may inspect all 256 shards, at most eight heads each, stopping after quota is available. Live evidence is never evicted. Expired index removal cannot release a record's quota while a lookup/response Arc still retains it. No SQL, signing, RNG, environment resolution or native callback runs under a shard lock. Allocation growth is fallible; cancelled/failed issuance releases its reservation.

Final reports allocate output metadata before their last clock-dependent source-time sample, then perform only arithmetic and callback-free publication/key/source checks. Later RPC response construction must preserve that same finalization rule. No atomic guarantee is made against state changes after the final local observation, and no extreme-throughput result is claimed before load qualification. Candidate tests and exact execution evidence are recorded separately in the private source handoff.

The requested-capacity charge is conservative: inline Checked/Binding payloads may also be included inside Record, and Arc header/alignment allowances and a bounded context reservation can overcount. It is not an exact allocator-layout/RSS measurement.

The signing-key registry publication is also fixed once per Source. Any registry change retires its usability; a replacement source must be prepared. This avoids retaining a distinct old registry graph per record outside the record capacity quota. Allocated HashMap buckets may exceed the entry-count bound and remain part of the explicitly separate opaque index baseline.

Independent observation also returns the cached canonical `scope_sha256` from the retained validated Binding. This authenticates the exact application/route/destination/header policy in addition to service/audience and the request digest; a shared source revision alone does not establish that scope. RPC/SDK integration must require this field.

The final pure constraint receives the same last native SourceTime sample and may only shorten admission. It does not change the signed expiry, retained record, or retention. An independent query must intersect its original sealed Admission at this sample, without resampling a clock.

The final observer repeats callback-free native publication/readiness/retirement checks after its last source/key publication loads. An overlapping observer that retires the exact retained Checked cannot be overlooked merely because this request sampled its clock earlier. This remains a local point-in-time fence, not atomic remote revocation.

## Administrator policy coordinates

When native Human receipts are configured, authenticated administrator user
responses expose `human_subject` for supported existing accounts. The detail page
and Hopae console package display the same coordinate used by the actual signed
native proof. The value derives from the configured issuer, immutable Store realm
and exact user ID; it is not an email, session, AAL or permission grant. Disabled
accounts retain their coordinate, while native eligibility checks still refuse
authentication. The metadata lookup does not establish primary/factor provenance.

List metadata uses one bounded Store query for at most 200 requested accounts,
joining current users, historical ID reservations and the actual realm. It does
not make a DB request per row. Unsupported legacy IDs remain visible in user
administration without a Human coordinate; they are not normalized, truncated or
given an alternative identity, and native proof issuance remains strict. The
issuer and realm cannot be supplied by an administrator API query parameter.


## Paired Human credential projection

`projection_receiver.human_observed_scopes` is an additive, empty-by-default
allowlist of exact `{service,audience,application,route}` tuples. Each tuple must
resolve to the actual configured native Human source and an exact native plan
with minimum AAL 1 or 2. A configured service may differ from the application
only for this explicit mapping; legacy Service/Workload requirements remain.
Multiple explicitly configured destination digests may share the tuple. Their
complete scope fingerprints form a fixed startup allowset; duplicate destinations
for the same service/audience/route refuse, even with a different header policy.
Incoming descriptors cannot add a destination, application or policy.

The optional `HumanObservedCredentialProjection.Project` endpoint requires
`permission_contract=4` and the exact bounded Pum `PermitValidationRequest`
bytes. One final H1v2 request digest binds authentication, permit and output;
the retained native Checked separately preserves its original frontend scope.
Only excluded fixed credential headers may be inserted afterward. The output
chain digest hashes the exact permission-query bytes, without re-encoding them.

The receipt RPC and projection runtime share the same actual Source Arc. Local
authentication must find its exact retained record; a signature alone cannot
reconstitute it. Pum independently observes the native source through the public
SDK. The predecode projection Admission starts before caller/decode work, and
its lower bound intersects authentication at the source's same final sample.
Pum delay, writer queue, secret work, reply allocation and final native Store
checks all consume that original bound. Refresh cannot renew the source proof.

All projection classes and endpoints reuse one Services-owned receiver-clock
Arc, including latched initialization failure. Human projection uses the same
Store-owned canonical paired ledger and nonce namespace as Service/Workload.
Native material/current SQL runs on that exact writer transaction. A separate
callback-free publication/key/readiness/cancellation fence runs after the last
receiver/registry check immediately before commit. It performs no SQL, clock
read, allocation or counted callback. This is a final local observation, not
an atomic distributed revocation guarantee. Cancellation before commit rolls
back both nonces; expiry/cancellation after commit discards output and leaves
the pair consumed. Reply allocations precede the final async native current
check. The retained secret buffer is zeroizing; temporary HeaderValue copies
are ordinary allocations, with no general memory-copy erasure claim.

Qualification distinguishes native Source/public SDK/actual Pum/paired secret
and replay tests from signed common-ledger vectors and fixed network/route
owner fixtures. These do not claim actual four-component Human HTTP dispatch,
operating activation, Human administration completion, or throughput results.
The private controlled RED removes only the final pure check while preserving
its postreceiver event/counter; the unmodified test then observes consumed rows
on cancellation. Historical failed setup/oracle runs remain separately recorded.

When Human receipts are configured, ordinary authenticated native Human Verify
also returns `x-hopae-human-policy-subject` and `x-hopae-human-policy-issuer`.
They derive from the actual verified UID, configured issuer and durable Store
realm/reservation under the existing request deadline. They never replace the
forwarded UID, source proof, independent observation or final permit. Missing
or unsupported coordinates refuse on this authorization path; administrator
metadata continues to omit unsupported legacy labels without hiding accounts.
The PEP must pin issuer/class/AAL, remove client lookalikes, and compare the final
opaque source observation rather than treating metadata as a capability.
