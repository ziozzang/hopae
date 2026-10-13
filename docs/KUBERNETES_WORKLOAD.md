# Kubernetes workload authentication

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/KUBERNETES_WORKLOAD.md)

Implemented native library: `auth_gateway::kubernetes::Connector`. It authenticates
Pod-bound ServiceAccount JWTs through a fixed trusted Kubernetes TokenReview API.
Root profile configuration, HTTP/HOP1 dispatch, console management, issuance and
production activation are not yet integrated. It does not implement an offline
JWT signature verifier or qualify a real Kubernetes cluster.

The owner supplies an HTTPS API origin, expected HTTPS issuer, cluster identity,
explicit workload audience, 1–1000 ms deadline, CA bundle and separate reviewer
credential. Secret material is absent from serialized Config. Only the configured
CA roots are trusted; redirects and environment proxies are disabled. The fixed
endpoint is `/apis/authentication.k8s.io/v1/tokenreviews`. Client JWTs are sent only
in `spec.token`; the Authorization header contains the reviewer's credential.
The reviewer needs narrowly scoped `create` permission for TokenReview, not access
to workload Secrets or arbitrary Role/Binding writes. Kubernetes authorizes this
API independently from the application policy.

JWT parsing is a refusal precheck, never authentication. It requires an allowed
signature algorithm identifier, matching issuer/audience, future expiry, optional
not-before validity, ServiceAccount namespace/name/UID and Pod name/UID. Legacy
unbound credentials and non-Pod-bound forms are unsupported. The trusted API must
then authenticate the original JWT and return matching username, ServiceAccount
UID, requested audience and exactly one matching Pod name/UID in user.extra.
Claims do not become evidence on parsing alone. The API is responsible for actual
signature and bound-object existence checks; nodes reported by the API are not
asserted to be verified identities. Pod extra metadata support must be qualified
for the chosen cluster version and authenticator.

The resulting principal is Workload, not Human: no human MFA assurance is inferred.
Issuer and cluster identity namespace it; a domain-separated length-prefixed hash
binds namespace, ServiceAccount name/UID and Pod name/UID. Existing stable-subject
encoding then produces the native identifier. Recreating either bound object changes
that identity. Evidence is service-scoped, expires at the earlier of token expiry
and one second after verification completion, and contains no credential or Pod
labels. The native caller supplies trusted time. There is no result cache: every
invocation contacts TokenReview, using pooled connections and at most 64 outstanding
requests. Three source failures open the cancellation-safe endpoint circuit for
30 seconds; client denial does not count as a backend failure. Reviewer 401/403,
malformed or contradictory positive attestations, TLS failures and oversized bodies
are source failures. Negative authentication, including its diagnostic error, remains
a credential denial and cannot open the source circuit.

Total network/body work is bounded by the configured deadline and 64 KiB response
cap. Response bytes are zeroized; typed parsing ignores the API's echoed spec.token
without allocating a token field. No request/response material is logged. Reviewer
and CA rotation require the native owner to recompile and retire the connector;
automatic file rotation and profile-revision fencing still need integration.

Kubernetes TokenReview has its own validity semantics: objects pending deletion
can remain acceptable until the documented deletion grace expires. A one-second
Hopae lease does not eliminate that API-side window. Strict early withdrawal needs
additional source deletion/revision fencing. Watches, long-stream revocation,
verified Pumgye associations, profile lifecycle and full-chain throughput remain
gates before production activation.

```sh
cargo test --locked --lib auth_gateway::kubernetes
cargo build --locked --example qualify_kubernetes_tokenreview
python3 tools/kubernetes_tokenreview_smoke.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview
```

The owned HTTPS mock verifies client/reviewer separation, attestation mismatches,
cluster namespace isolation, response limits, CA/proxy/redirect refusal and circuit
opening. It deliberately uses fictional tokens: it proves the native transport and
attestation contract, not a real API server's JWT signature or deletion behavior.
See [Kubernetes bound token verification](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#verifying-and-inspecting-private-claims)
and [bound token lifecycle](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens).
