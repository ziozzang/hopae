# Human native ingress transport prerequisite

This change shares the exact private native Human owner from `Services` with the HTTP gateway and adds an **unmounted** private gRPC ingress adapter. No Human RPC, receipt issuance, public capability constructor, or production Human activation is introduced. Existing Service and Workload mounts remain unchanged.

The adapter samples the original native Admission **before caller authentication callbacks and before the first body poll**. Only an authenticated caller receives a private cloneable holder containing one `Option<Admission>` behind a mutex. Generated tonic decoding carries that holder in request extensions. The native exchange explicitly transfers it to the HTTP gateway; the gateway consumes it once, checks the exact owner, and passes the original Admission to the existing native Engine. Missing tokens never trigger a fresh admission. Wrong-owner, duplicate-consumption, mixed Human/Workload markers, expired age, and readiness loss refuse.

The same readiness owner remains inside Admission after consumption, through asynchronous Engine/store work, Witness finish and subsequent Checked current checks. A witnessed failure retires the original evidence. This is an observation-based local fence, not an atomic guarantee against a shutdown immediately after the final check. Original BOOTTIME, wall-floor, deadline and quantization arithmetic are retained; no budget is renewed after decoding or caller work.

Tests mount the existing generated Authentication Verify service **only in an owned test harness**, authenticate an actual fixture caller, and use real owned OIDC login, production gateway and native Engine capture. They distinguish successful decode from original-age refusal, caller-callback age, invalid caller before body polling, cancellation and semaphore release, one-shot ownership, mixed markers and readiness withdrawal during store await or after Checked creation. This proves transport/owner mechanics; it does not qualify a future Human wire contract or an externally available Human endpoint. The controlled body fixture adds only a development `http-body` dependency.

## Retained current checks

A private Engine-produced `Checked` can repeat the same native owner checks
without keeping or reconstructing raw cookie credentials. Its retained scope
was established by the actual Engine; this method has no public constructor or
caller-supplied subject. Original admission, readiness, provider/material/app,
durable session/user/primary/factor checks and retirement apply unchanged.
Explicit-input checks still require the exact original scope. A failed explicit
check also retires subsequent retained checks, including overlapping awaits.
This is a prerequisite for source records, not receipt issuance or RPC activation.
