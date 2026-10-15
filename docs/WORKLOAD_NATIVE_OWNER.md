# Native Workload receipt owner

This stage activates only native Workload authentication receipts and their
source-time observation. Pum Workload permit RPCs, consuming Hop projection and
Hangang Workload dispatch remain separate integration gates. Human receipts
require an independent native session/handle/user/factor owner and are not
coerced to Workload or Service. Existing Service APIs and defaults are unchanged.

## Explicit configuration

Add to the existing `receipt_issuer` object:

```json
"workload_receipts": {
  "scopes": [{"service": "orders", "audience": "orders-api"}],
  "capacity": 131072
}
```

Scopes must be a unique subset of the issuer's existing declared scopes, match
configured applications and have native Kubernetes TokenReview profiles for
that service. Activation requires an authenticated mTLS gRPC listener and a
supported suspend-inclusive native clock (Linux BOOTTIME); unsupported platforms
refuse this optional activation, while ordinary defaults remain unchanged.
The logical `identity_authority_epoch` reference must be at most40 ASCII bytes
when enabling Workload. It is not the TokenReview issuer URL or cluster realm.
No token, signing seed, CA value, caller identity or AAL is accepted in this
object. Existing native credential material references and TLS trust apply.
Absent `workload_receipts` leaves the new RPC service unregistered.

`WorkloadAuthenticationReceipts.IssueObserved` invokes the existing actual
caller/parse/gateway/profile authentication pipeline. A private request extension
carries an original source attempt; no external header can construct it.
Only an actual `kubernetes-tokenreview` native Workload result can become
`CapturedWorkload`. Local Service keys, service compositions, API relays, Lua,
client identity/AAL claims and Human sessions cannot issue through this boundary.
The existing stable subject hash and wire kind3/AAL0 are preserved.

## Original source age and current owners

Before any provider work, the issuer reserves capacity and samples its own
BOOTTIME clock. Its deadline is at most entry+1000ms; the native token/provider
UTC expiry can only shorten it. Conversion uses the original trusted native wall
sample, removes a full millisecond for wall/source quantization, and never starts
a new budget after TokenReview, signing, Observe or a retry. A current native wall
check can additionally refuse expiry or reversal; it does not extend the local
lease. Signed receipt expiry itself is bounded by that original source deadline.
Remaining admission removes a further millisecond before export. Owner ticks are
not UTC. For Workload identities, the public strict UTC verifier reserves and
refuses the complete canonical `workload_epoch::decode` grammar. Legacy Service
authority names beginning `wobs1:` and generic strict UTC Workload identifiers
such as `wobs1:legacy` retain existing behavior. The exact canonical new grammar
is a reserved namespace: a prior generic UTC caller that deliberately used that
same complete form must migrate its authority identifier. There is no native
production strict Workload receipt issuer today, but the generic library supports
free identifier epochs, so this compatibility boundary is explicit. Malformed
`wobs1:` identifiers still follow the old generic UTC identifier/signature rules;
the NEW Workload RPC strictly decodes the canonical grammar and exact process
nonce and record, with no fallback to that generic UTC path. Native Workload
records retain only ObservedChecked signature/registry evidence and cannot be
passed as a strict Checked consumption capability.

Every issuance checks native current profile/application, caller and source time
around provider/RNG/signing work and after signature/key verification. Workload
captures the exact application publication before TokenReview. Signing and
observation bind the exact profile/application and key-registry Arc generations.
Owner replacement, expiry and original-capture failure retire that capture;
restoring prerequisites cannot revive it. BOOTTIME read failure or a true read
below an already-published pre-read clock floor retires the whole domain
irreversibly. Concurrent earlier reads completing later do not falsely retire it.
Recovery requires a fresh native authentication under a newly initialized valid
process clock domain, not a numeric reconstruction of an old proof.

`ObserveTime` requires an exact signed-context/receipt-hash lookup in this issuing
process's original record set. Missing, expired, evicted or restarted records
refuse; signature validity alone cannot create a new record/deadline. Observation
only shortens the original proof and does not rerun TokenReview or retain the raw
token. External Pod/SA revocation is therefore bounded point-in-time evidence,
not instantaneous invalidation: fresh issue must perform a new real TokenReview,
and an old record cannot extend beyond its original maximum one-second bound.
The API fixture tests do not claim real Kubernetes JWT signature validation or
live-cluster Workload end-to-end qualification.

## Capacity, memory and concurrency

Capacity defaults to131072 original attempts/records and is configurable in
1..1048576. This can hold100000 simultaneous source records without a structural
16384-record ceiling; it is not a100k/s performance result. A global semaphore
reserves capacity before expensive provider work. Cancellation before publication
releases the attempt; published records retain it until original-expiry cleanup.
Full capacity refuses rather than evicting a still-admissible proof.

Records use256 independently locked hash-map/expiry-minheap shards. Each shard
accepts at most2*ceil(capacity/256) records (1024 at default), additionally
bounding retained hash-map/heap allocation after traffic skew. Skew exhaustion
refuses without evicting a live record; it cannot bypass global capacity. Lookup clones
one Arc under a short lock. Insert is O(log shard_size); it never clones or scans
a whole record map. Normally each new attempt visits one round-robin shard and pops at
most8 expired heap entries. Only when global capacity is exhausted, a pressure
sweep reads at most256 atomic heap-head hints, locks only expired shards, pops
at most8 per visited shard and stops immediately when a permit is available.
Hints are updated with the heap under the same shard lock; a capacity1 record in
a distant shard is reclaimed on the next request after expiry, rather than
requiring256 rejected requests. No still-live source record is removed. No provider, signing, clock/current-owner callback or
await runs under a shard lock. Expired records may remain resident when idle;
memory stays capacity-bounded and subsequent traffic performs bounded cleanup.
Owner references in attempts are weak to avoid a record/owner retention cycle.
No public reinsertion or lease-restoration endpoint exists.

On the tested64-bit target, `size_of` was Record112, Attempt56, Checked176,
heap-entry40, map-entry40 and shard72 bytes. Per-record Arc allocation headers,
allocator rounding, hash-map load/slack and heap spare capacity are additional;
approximate record storage is0.5–1KiB each (roughly64–128MiB at default capacity,
0.5–1GiB at maximum), plus256 shard structures,2KiB of expiry hints and shared captured
profile/application/key-registry snapshots. Distinct large retained generations
can add memory. These are structural estimates, not measured peak RSS promises;
operators should choose capacity with memory headroom. The functional100000-record
test checks resident lookup, no early eviction, capacity accounting and bounded
cleanup; it does not benchmark authentication throughput.

## Replay is a separate owner

These ephemeral records are an authentication source eligibility lookup only.
They do not consume a nonce and do not replace or shorten the durable paired
Hop authentication/permit replay ledger. Record expiry/withdrawal/cleanup never
deletes a consumed replay entry. Future Workload projection must reuse the same
canonical signing-key/purpose/nonce ledger identity and full signed proof upper
retention bounds across principal classes, RPCs and contracts. See the
[additive protocol contract](WORKLOAD_OBSERVED_PROTOCOL.md).
