# Human observed SDK and additive protocol

This document describes the wire/SDK boundary; these types alone activate no
Human source or route. A separately qualified optional native source/RPC adapter
uses the SDK contract. Permission, contract4 projection and Root activation remain
separate work. SDK-only authenticated test peers are fixture signers, not native
Human proof; actual Engine/session/provider RPC qualification is recorded separately.
Existing Service/Workload RPCs, types and v1/v2 hash vectors remain unchanged.

`HumanAuthenticationReceipts.IssueObserved/ObserveTime` use the appended descriptor
in gateway.proto. HumanFinalRequest contains metadata only: v2 contract2, final
method/target, body SHA256 and length, route ID/revision, destination32 and fixed
header-policy revision/slots. No complete body is transmitted. The SDK prepares
this metadata from actual complete transformed bytes via request_binding_v2 and
an immutable compiled fixed scope/header manifest/reserved-name policy. The max
body remains16MiB, headers remain bounded64KiB verification metadata; encoding
and decoding RPC frame caps are128KiB, not a new64KiB request ceiling. Existing
native header limits are64headers, name1..128bytes, value<=16384bytes, and
aggregate includes6framingbytes per header within65536bytes. Actual HTTP header
name/value validation and reserved x-hopae-gateway-key refusal match the native
pipeline. H1 bind_actual computes body SHA once and returns only computed public
metadata with private fields; existing digest bytes remain unchanged. No raw-digest
issuance constructor exists.

Canonical source epoch:
`hobs1:<32lower-nonzero-process-nonce>:<authority<=40>:s:<source-scope-revision>:a:<application-generation>`.
Revisions are positive safe-u64 canonical decimal. Authority uses existing ASCII
identifier grammar. TimeReply field6 is **source_revision**, not a profile or user
revision. Identity is kind1, actual AAL1, 2 or 3 (3 only for applications that opted in, Hopae ADR-0018), `human1:`+64lowerhex. Identity revision
and credential generation must each be positive safe-u64 but need not equal the
source revision or each other. No global user floor is maintained: one user's
change cannot retire unrelated users. Fixed source/app/key-registry floors are
configuration publication metadata; native per-user current owners remain required.

`IssuePrepared` has private fields and is produced only by actual-body `prepare`.
`ObservationRequest` has separate private fields and is produced from untrusted
public context/receipt plus the downstream owner's expected digest. It cannot be
passed to IssueObserved. `observe` independently verifies signature and queries
ObserveTime before creating opaque `Observation`; neither preparation nor public
signature/context is evidence of current admission by itself. The SDK pins mTLS
peer/CA, caller/key/issuer/authority/scopes and explicit clock rates. Scope app_id
is fixed metadata; native producer must bind verification's actual public app scope
and session to that configuration, not promote a request header into identity.

The SDK charges whole operations/exchanges, checks signed source-time report/hash/
request correlations and process domain, and restricts consuming refresh to the
old original deadline while retaining independent signed-proof replay retention.
Clock failures retire the client irreversibly. Configuration owners must retire
clients on replacement; native server/consumer owner and post-callback fences are
still mandatory. A valid SDK observation is authentication/time evidence, never
permission. A later actual Engine/H0 source→publicSDK→Pum→same paired ledger→Root
qualification is required before claiming Human wire or runtime completion.

Sensitive new descriptor/proof DTO Debug is redacted. Examples/tests use reserved
synthetic identities and private ephemeral credentials; no payload logging.

## Authenticated source-scope report

HumanReceiptTimeReply field10 `scope_sha256` is the canonical fixed scope
fingerprint from the **exact source proof record**, not a request parameter. It
binds service/audience/app/route/revision/destination/header-policy revision and
sorted slot names under `human_scope`'s domain. Reserved names are validated but
are not encoded; actual slot configuration remains fixed and validated. This
metadata is not route ownership, permission or proof that a malicious PEP sent
particular body bytes.

Clients compile/cache fingerprints once with their fixed header policies and reject
duplicate canonical fingerprints, including equivalent slot sets whose reserved
filters differ, so every accepted report selects exactly one configuration. Issue
requires the exact selected preparation scope; another configured scope sharing
service/audience cannot substitute. Observe-only preparation retains its existing
signature: the authenticated ObserveTime report selects a matching configured
scope, with exact service/audience and proof/hash/time correlation checks before
opaque evidence exists. Missing, malformed, unknown or unconfigured scope hashes
refuse. `Observation::scope()` exposes that immutable validated configuration as
metadata only. Consuming refresh must retain the same fingerprint, even if the
client permits other scopes. Downstream native authorization must still match
that scope to its own fixed resource/route/plan configuration and current owners.
This additive unreleased Human field does not alter Service/Workload messages.
