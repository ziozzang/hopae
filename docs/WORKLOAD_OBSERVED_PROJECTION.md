# Workload observed credential projection (contract3)

This additive opt-in path validates native Workload authentication and a separate
Pum Workload permission observation before returning a credential for the exact
bound upstream request. Authentication alone grants neither resource access nor
credential output. Existing Service strict/observed endpoints stay class2-only.
The Workload endpoint accepts class3/AAL0 and permission_contract3 only; no class,
method, trust, source or UTC fallback is selected from request claims.

## Activation

`projection_receiver.workload_observed_scopes` is the ONE native output activation
model. Its default is empty; no Workload projection RPC is registered then.
Each exact `{service,audience}` must be unique, belong to the configured native
`receipt_issuer.workload_receipts.scopes`, and have an existing compiled credential
plan for that service/audience admitting AAL0. Explicit valid
`observed_clock_rates` and authenticated mTLS gateway configuration are mandatory.
Unknown/duplicate scopes, unknown fields and incomplete dependencies fail startup
validation. Existing Service plans/activation are unchanged. Do not introduce a
second plan-class fallback model or treat source authentication opt-in as output
opt-in.

The following fragment extends an otherwise complete native receiver config;
paths and environment references are reserved illustrative startup metadata:

```json
{
  "projection_receiver": {
    "authority": {
      "address": "https://pumgye.example.test:443",
      "server_name": "pumgye.example.test",
      "ca": "/etc/owned/pumgye-ca.pem",
      "certificate": "/etc/owned/hopae-client.pem",
      "key": "/etc/owned/hopae-client.key",
      "token_env": "OWNED_PUM_CALLER"
    },
    "observed_clock_rates": {"source_ppm": 500, "receiver_ppm": 500},
    "workload_observed_scopes": [{"service": "orders", "audience": "orders-api"}],
    "secrets": [{"reference": "vault:orders", "token_env": "OWNED_ORIGIN"}]
  }
}
```

Use native TokenReview profiles whose cluster matches the profile realm. Do not
put bearer secrets, token claims, public-key replacements or request-selected
URLs into this scope list. Native issuer/receipt-key/projection-plan configuration
and the existing reference-only secret configuration remain required.

## Exact chain and owners

The dedicated WorkloadObservedCredentialProjection.Project RPC requires:

- Fresh bounded outer ProjectionRequest.request_id equal to the top-level encoded
  PermitValidationRequest.request_id. Inner native request/permit IDs retain their
  original matching issuance lineage.
- Immutable bounded decoded request and exact original permission_query bytes.
  `chain_sha256` is SHA256 of those original bytes. No decode/re-encode allocation
  or new protobuf canonical restriction was added; existing ingress rules remain.
- Both authentication/permission contexts kind3/AAL0, matching canonical wobs1,
  subject/profile/credential generation/service/audience/final request hash;
  exact authentication proof SHA, native resource/action/route/destination and
  plan constraints. Cross-class or Service epoch input refuses.
- The actual local issuer-affine Workload Record. A valid signature with a missing,
  expired, restarted or retired source record cannot reconstruct evidence.
- An actual authenticated response from the fixed configured
  WorkloadObservedProjectionPermits.Observe endpoint. Service Observe is never a
  fallback. Exact signed pobs1 domain, receipt SHA, proof_remaining, policy,
  network, route and plan revisions and cache_ttl0 are checked independently.
- Existing compiled exact plan scope and credential reference, with current
  profile/application/plan/key/caller/cancellation owners throughout secret work.

The Pum dependency is pinned to immutable
`dd62d6559613923f421cb76f0e65aea48224ea76`; SDK wire types are pinned there to Hop
`4ea3e1473de61d6b46f5420efe481c126790d800`. No uncommitted/path Git dependency is
required. The private typed Workload adapter reuses unverified wire-bound checks,
not Service authentication validators. No public signature/numeric TTL/allow-flag
constructor grants a projection capability.

## Time, replay and final output

The native source's original pre-TokenReview maximum1second is never renewed.
Local source, Pum permit and output clocks are independently converted with actual
pre-call ReceiverClock anchors and shared rate/quantum arithmetic. Both local
clocks are BOOTTIME on the same host but have distinct origins; even local source
reports use the ordinary exchange conversion. Foreign absolute ticks are never
intersected or treated as UTC. Zero admission refuses; cache_ttl0 is not a lease.
Long RPC delay can exhaust the conservative interval even before raw source
expiry (e.g.600ms exchange and~400ms remaining). Budgets/rates are not relaxed.

Service and Workload share EXACTLY the existing paired durable transaction,
replay-key function, IDS/COUNT storage and retention rules. Replay identity is
issuer+purpose+nonce, excluding class, endpoint, contract number and source-cache
key. Consuming either member refuses a new mate atomically, including a pair in
another principal class. Source Record cleanup is separate from replay cleanup.
Full signed retention upper remains distinct from shorter admission; unknown
receiver generations retain tombstones and capacity fails closed.

Blocking-worker cancellation closes activity irreversibly. Native guards run
before/after secret work and after callbacks; profile/application/plan/key and
source Record owner identity remain captured. Errors/timeouts do not produce an
output. A late failure after a committed pair keeps consumption evidence; a caller
must not reset old nonces to recover a lost credential response.

Both observed Service and Workload now use one PRIVATE reply finalizer: allocate
reply strings/hash/domain and pending secret bytes first, run final caller/source
guard, sample remaining local proof budgets, perform pure owner/activity checks,
then assign numeric report fields and move pending bytes without further
allocation/callbacks. The pending `Zeroizing<Vec<u8>>` buffer is zeroizing on failure; the temporary
`HeaderValue` copy is ordinary memory, so this does not promise erasure of all
transient copies. Opaque outputs are
non-Clone/non-Debug/non-serde; protobuf secret Debug remains redacted. This does
not turn the report into a remote revocation lease or guarantee remote byte
recall. The Root consumer must preserve its independent auth/permit/output bounds
and actual below-TLS final dispatch/write fences.

## Qualification boundary

Tests exercise real owned TLS TokenReview→production native authentication→mTLS
contract3 output→shared SQL replay, with an owned typed Pum Observe signing peer.
That peer is NOT evidence of actual Pum policy evaluation. Separate Pum native
policy tests, real Kubernetes projected JWT/TokenReview, actual OSprocess restart
and complete Root backend nondispatch qualification remain integration gates.
Same-process fresh native-owner/server instances are not OSrestart evidence.
Functional tests do not establish throughput/pooling completion.

The focused suite covers default-off/unknown/duplicate scope config, exact raw
query hash, successful typed output and redaction, repeated pair refusal,
cross-class same nonce consumption in both directions, Service endpoint refusal
of Workload input, permit deny/hash/delay failures, app/profile/plan/key retirement,
blocking-worker cancellation, final callback withdrawal, and reply-allocation
expiry/clock retirement. Existing Service actual-runtime regression is retained.
