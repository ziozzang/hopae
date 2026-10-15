# Native observed paired projection

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/OBSERVED_PROJECTION.md)

The observed path is additive. Strict `CredentialProjection.Project`, contract 1,
and its UTC ledger semantics remain separate. Observed contract 2 uses the
`ObservedCredentialProjection.Project` service and the exact bounded Pumgye
`PermitValidationRequest` bytes in `permission_query`. The reply's `chain_sha256`
is SHA-256 of those exact bytes, including any accepted protobuf unknown fields;
no decode/re-encode normalization occurs.

Configure the existing fixed mTLS `projection_receiver.authority` and explicitly
add `projection_receiver.observed_clock_rates`, for example:

```yaml
projection_receiver:
  observed_clock_rates:
    source_ppm: 500
    receiver_ppm: 500
```

These are operator-established physical error bounds for the Pumgye source and
Hopae receiver, each strictly less than 1,000,000 ppm. They are not automatically
qualified hardware measurements. Missing rates leave strict projection available
and refuse observed projection before a permit query or credential resolution.
Same-process Hopae authentication uses equal-rate conversion because its
progressing source and receiver share this host's BOOTTIME backend; UTC forward
steps can only accelerate the authentication source and refuse/shorten admission.

Hopae first checks its exact issuing authentication clock domain and actual live
profile/application/key owners. A sealed local authentication observation retains
its original receiver deadline. A persistent fixed native Pumgye client verifies
the permit signature with receiver-owned keys, calls `ObservedProjectionPermits.Observe`
over mTLS with a fresh RPC correlation, and checks the signed Pumgye domain,
digest, full signed remaining lifetime and owner revisions. Caller-supplied reports
or runtime numeric bounds cannot construct the native projection admission.
Numeric report assembly for the direct SQL fixtures is test-only.

The actual native plan owner resolves credentials inside one Immediate SQLite
transaction with both nonce reservations. Signature/registry evidence is separate
from observed time. The transaction checks immutable owner generations and
registry contents before and after work; a precommit fence observing cancellation,
expiry, callback failure, secret failure or registry changes rolls back both
reservations and owner work.
A committed result remains consumed if its reply is lost or final output refuses.
The guarded output has its own `hproj1:<32 lowercase hex startup generation>`
clock identity. Its duration floors the actual remaining BOOTTIME budget after
credential work and final callbacks. It never takes a minimum of auth/permit
absolute expiry coordinates. Root must intersect this report with its original
prerequisites using a before/after RPC interval and recheck dispatch ownership.

## Durable replay storage and restart

Both modes use the exact existing replay identity:
SHA-256 of the v1 consumption domain separator, issuer length and bytes, proof
purpose, and nonce. There is no mode prefix. Both share `projection_nonce_id:` and
the capacity counter, so switching adapters cannot consume a nonce twice.

Strict rows retain their numeric UTC value and strict expiry index. Observed rows
use a deny-unknown-fields version-2 JSON value containing receiver generation,
full signed retention ticks and source domain, plus a separate generation-scoped
ordered expiry index. Cleanup deletes at most 128 rows per transaction and uses
only this exact receiver instance's BOOTTIME ticks. A shorter admission/prerequisite
budget cannot shorten either proof's full signed replay retention. UTC or source
clock forward steps never collect observed rows.

After receiver restart, rows from unknown receiver generations remain tombstones
indefinitely. Their numeric ticks are never compared with the new generation.
There is no startup sleep, arbitrary grace period, inferred domain retirement or
clock reset cleanup. Capacity exhaustion fails closed, including unknown-generation
tombstones. Operator-led reconciliation requires a separately established positive
source retirement/ownership proof; no such reconciliation API is supplied here.
The authentication source and projection owner must be the exact issuing runtime.
DB loss/rollback, cloning a live source generation, concurrent copied owners or VM
restore are not qualified recovery operations; stop/fence the old owner and rotate
its issuing domain before restoring service. Random generation alone is not a
clone or rollback detector.

## Validation scope

Native SQL tests cover independent source offsets, paired replay, cross-mode
identity, rollback, secret failure, lost response, shortened admission versus full
retention, UTC-forward cleanup isolation, unknown-generation restart retention,
capacity refusal and final output expiry/retirement. A generated mTLS fixture uses
actual Hopae identity/key/plan owners, native SQL and the observed projection RPC;
only the Pumgye source peer is a protocol fixture. Full four-process release
qualification and restore/clone qualification are separate from those tests.

