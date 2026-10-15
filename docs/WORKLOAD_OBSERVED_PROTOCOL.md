# Workload observed protocol: declarations only

This is an additive protocol contract, not an activated Workload authentication,
permission or projection implementation. No server registers the new services in
this change. Existing Service RPCs, messages, method paths, trust, epochs and
default configuration keep their existing meaning. Workload is wire kind3/AAL0;
Service stays kind2/AAL0. Neither a parser nor generated protobuf message is an
authentication capability. There is no new strict/UTC Workload endpoint.

The initial source is the actual native Hopae Kubernetes TokenReview flow,
explicitly enabled for the application scope. A caller cannot select identity,
kind, assurance, source revision or verification time. Successful identity is
not an end-resource grant: Pumgye must still evaluate native typed Workload rights
in its same policy compiler/View, with network, role, class and assurance checks.
Human sessions and factors remain a separate future contract.

## Additive endpoints

Package `hangang.hopae.v1` declares:

- `WorkloadAuthenticationReceipts/IssueObserved`: WorkloadReceiptRequest to
  WorkloadReceiptObservedReply.
- `WorkloadAuthenticationReceipts/ObserveTime`: WorkloadReceiptObservationRequest
  to WorkloadReceiptTimeReply.
- `WorkloadObservedCredentialProjection/Project`: existing ProjectionRequest to
  existing ObservedProjectionReply, with permission_contract exactly3.

The dedicated receipt messages retain the bounded field tags of their matching
Service shapes. WorkloadReceiptTimeReply.clock_domain is **exactly the32
lowercase nonzero hex process nonce** in its signed epoch, without a prefix or
owner/generation suffix. owner_now_ms is from that exact issuer BOOTTIME domain.
remaining_ms is admission-only; cache_ttl_ms is always0. All existing correlation,
canonical receipt/context, hash, safe-integer, size, rate and key-owner checks
remain mandatory in future handlers. New request/proof Debug implementations
redact verification headers and receipt bytes. No raw projected token is logged.

Pumgye's corresponding future additive service is
`WorkloadObservedProjectionPermits`, with Issue(AuthenticatedResourceRequest)
and Observe(PermitValidationRequest), reusing its existing observed permit reply
messages. This document does not add that service to Hopae's package or activate
it in Pumgye. Old Service endpoints must reject Workload; new endpoints must reject
Service, Human, unknown kinds and nonzero Workload AAL, without fallback.

## Canonical signed owner epoch

`hopae_grpc::workload_epoch` encodes/decodes pure owner metadata:

    wobs1:<nonce32>:<authority>:p:<profile>:a:<application>

nonce32 is fresh cryptographic process data, exactly32 lowercase hex characters,
not all zero. authority is an exact operator-trusted reference of1..40 ASCII
characters from `[A-Za-z0-9_.:-]`; no truncation, hashing or case normalization.
Profile and application are canonical unsigned decimal1..9007199254740991,
without leading zero/sign/whitespace. The whole value is at most128 bytes (maximum
encoded length117). Parse the fixed prefix/nonce, then the rightmost `:a:` and
preceding rightmost `:p:`; re-encode and compare bytes. Colon-bearing authorities
remain unambiguous because numeric suffixes contain no colons.

Example:
`wobs1:11112222333344445555666677778888:example-hopae:p:7:a:11`.
The nonce is fictitious. Parsing this string proves no identity or lifetime.
Identity revision and credential_generation both equal profile for this initial
profile-owned source only. A different source needs a new reviewed versioning
contract. The logical epoch authority is not a TokenReview issuer URL or cluster
realm; those stay exact separate subject-hash inputs. Existing stable Workload
subject hashing uses discriminator byte2, whereas Workload wire kind is3: never
substitute one enum's number for the other. Canonical subjects stay `s_` followed
by48 lowercase hex characters; that prefix alone does not mean Service.

## Original source admission and replay retention

A native Workload owner MUST capture BOOTTIME before all authentication/store/
network callbacks. Its original deadline D is no later than entry+1000ms and the
conservative original token/provider expiry. The signed Workload authentication
receipt expiry MUST be <=D in that same source domain. Signing, profile renewal,
RPC retries, Observe and later success cannot start a new proof lifetime. Native
wall/token-expiry checks are additional restrictions, not substitutes for elapsed
age. Final callback/sign/output checks retain the original stamp and check owners
after the last clock dependency. No fake UTC or foreign absolute-time minimum.

An optional bounded source-record lookup must bind the exact receipt hash/nonce,
process domain and captured profile/application/key owners. Missing, evicted,
retired or replaced record MUST refuse; never rebuild a fresh deadline from a
client context or remaining_ms. A stateless equivalent is allowed only if signed
expiry carries the exact original deadline and current native owner checks remain.
Capacity exhaustion refuses, reservations precede expensive work, and publication
must not expose a receipt before its mandatory record exists. No raw token needs
retention for this nonrenewable design. External Pod/SA revocation has the measured
bounded lag of initial TokenReview plus this original proof; do not claim instant
withdrawal or fresh TokenReview on Observe. Stronger semantics need a separately
reviewed protected token-reference design.

Clock read failure, reversal/discontinuity or captured-owner replacement
permanently retires the original observation capability. Peer recovery or a later
normal clock read cannot resurrect it. Unknown process clock continuity retires
that domain; recovery needs a new valid source domain and fresh authentication.

Source eligibility, optional source-record storage and durable consumed-nonce
retention are different lifetimes. An expired source record can be removed only
with permanently fail-closed absence semantics. Durable paired auth/permit nonce
entries MUST survive until full signed proof retention upper bounds, even when
admission is shorter or a source disappears. Authentication retention derives from
verified signed expiry and authenticated owner_now; remaining_ms cannot shorten
it. Pum's proof_remaining_ms is retention-only; its remaining_ms is admission-only.
Use existing before-RPC receiver anchors, explicit rate/quantization arithmetic,
intersecting admission and nonshortening retention. No numeric helper grants
identity or permission.

Contracts1/2/3 and Service/Workload share the SAME atomic paired replay ledger and
existing signing-key/nonce identity rules. RPC name, class, contract number or a
changed context digest cannot create a fresh replay namespace. Source-record
capacity/cancellation must not evict or reset durable consumption records.

## Native policy and migration gates

Optional Pum workload_users selects typed Workload grants in the SAME compiler,
CompiledPolicy and exact source View as legacy users. No fallback in either
direction. Same subject bytes in both maps remain isolated; Workload AAL0 cannot
satisfy positive assurance requirements. Policy/route/plan/network/application/
profile/key withdrawal remains a real current-owner fence.

Mapping v1 preserves its old legacy users output, candidate_only meaning and
serialized fields, including old workload-coordinate inputs. It never silently
becomes a typed Workload grant. Both template maps must be empty. Opt-in mapping
v2 writes explicit Workload grants only to workload_users and native_subject
grants only to legacy users; a single grant cannot assert both. Candidate version
and class metadata must expose this distinction, without adding empty/null fields
to v1 output. Source activation still requires existing authenticated publication
and exact View ownership; Kubernetes RBAC matching alone grants no application
access.

Before activation require actual native TokenReview -> typed Pum resource Allow ->
shared consuming Hop projection -> Root opaque SDK/raw I/O gate -> independent
backend-counter qualification. Include clock/callback/sign delay, missing record,
capacity/cancellation, original expiry, restart nonce, class/epoch/method mismatch,
full signed replay retention, v1 output compatibility, v2 typed isolation, source
withdrawal and measured external revocation lag. Synthetic signatures, generated
clients and these parser vectors do not establish end-to-end support. Preserve
Service strict/observed regression gates. Parent controls dependency publication,
server activation, signing and deployment.
