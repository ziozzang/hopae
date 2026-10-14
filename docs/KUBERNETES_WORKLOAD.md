# Kubernetes workload authentication

<!-- doc-rev: 3 -->

[Documentation](README.md) · [한국어](ko/KUBERNETES_WORKLOAD.md)

Implemented native library: `auth_gateway::kubernetes::Connector`. It authenticates
Pod-bound ServiceAccount JWTs through a fixed trusted Kubernetes TokenReview API.
Reference-only root/profile configuration, HTTP/HOP1 dispatch and console overview
are integrated. Workload receipt issuance and real-cluster production activation
remain pending. It does not implement an offline
JWT signature verifier or qualify a real Kubernetes cluster.

The owner supplies an HTTPS API origin, expected HTTPS issuer, cluster identity,
explicit workload audience, 1–1000 ms deadline, CA bundle and separate reviewer
credential. Secret material is absent from serialized Config. Only the configured
CA roots are trusted; redirects and environment proxies are disabled. The fixed
endpoint is `/apis/authentication.k8s.io/v1/tokenreviews`. Client JWTs are sent only
in `spec.token`; the Authorization header contains the reviewer's credential.
The reviewer needs narrowly scoped `create` permission for TokenReview plus
namespace-scoped `get` on Pods/ServiceAccounts, fetched as metadata, not access
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
and one second after authentication start, and contains no credential or Pod
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
and CA rotation require the native owner to recompile and retire the connector.
The runtime preserves a connector circuit across publication only when connection
configuration, actual CA/reviewer material, prefix and service/realm binding match.
Automatic file rotation remains pending; profile publication uses the existing
owner snapshot fence and refuses a retired in-flight HTTP/HOP1 result.

Kubernetes TokenReview has its own validity semantics: objects pending deletion
can remain acceptable until the documented deletion grace expires. A one-second
Hopae lease does not eliminate that API-side window. Live object checks below provide early bound-object withdrawal; watch-backed
source/follower revision fencing remains pending. Watches, long-stream revocation,
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

## Native profiles and HTTP/HOP1

A profile may contain `kubernetes_tokenreview` alongside native keys and API relay.
The connection uses separate native environment references for CA PEM and reviewer
credential; neither value is part of the owner document or UI. Example fragment:

```json
{
  "kubernetes_tokenreview": {
    "connection": {
      "api_origin": "https://kubernetes.example.test/",
      "issuer": "https://issuer.example.test",
      "cluster_id": "example-cluster",
      "audience": "orders-workload",
      "namespaces": ["blue"],
      "timeout_ms": 500
    },
    "ca_pem_env": "HOPAE_KUBERNETES_CA_PEM",
    "reviewer_token_env": "HOPAE_KUBERNETES_REVIEWER",
    "token_prefix": "k8s:"
  }
}
```

Profile realm must equal cluster_id. A mandatory 2–32 character prefix ending in
`:` routes only marked credentials to TokenReview and is stripped before the API
request. Local keys cannot occupy that prefix. When API relay is also configured,
it needs a different explicit prefix; unmarked, invalid or failed Kubernetes
credentials never fall through to another source. Presented credentials remain
subject to the compiled profile's network gate before any remote request and to
optional bounded Lua eligibility afterwards. The whole presented credential,
including prefix, is at most 4096 bytes; native bound identifiers are at most 128.

HTTP and HOP1 use the same runtime, publication fence and current application
step-up checks. Responses identify `workload`, service and canonical native
subject with AAL 0; no machine proof satisfies a human step-up rule. Hangang's
trusted native-Hopae-to-Pumgye parser accepts canonical workload AAL 0 and refuses
human assurance, noncanonical subjects, duplicate metadata and network-only identity.
Console package 0.1.7 shows TokenReview, issuer, cluster, audience, allowed namespaces and routing prefix
with the existing native owner editor/publication path. HTML-like values remain text;
viewer controls remain read-only.

The owned HTTPS/HTTP/HOP1 scenario covers mixed local/workload authentication,
credential routing isolation, source/client failure classification, human step-up
refusal and profile removal during a blocked TokenReview. The TLS source is a mock;
actual cluster signature/deletion semantics, scale-out source fencing, long-stream
identity revocation, mapped Pumgye grants, workload receipt issuance and full-chain
performance remain qualification gates. Internal production profiles may stay
native-only even when this compiled capability is deployed.

## Live bound-object checks and actual API qualification

`connection.namespaces` is mandatory: 1–128 distinct DNS-label namespaces, checked
before any remote request. Unknown namespaces are credential denials, not source
failures. Negative TokenReview can omit authenticated/audiences and return user:{};
this canonical API shape is a denial even with an error diagnostic. An empty or
contradictory positive user remains a source failure.

A successful review is followed by authenticated GET of current ServiceAccount
and Pod PartialObjectMetadata, limited to 16 KiB each, using the same fixed CA/API
and total deadline. Missing objects, changed UID/name/namespace or non-null
`deletionTimestamp` deny immediately; transport/permission/malformed metadata
errors fail closed and count towards the source circuit. No full Pod spec or Secret
is fetched. Bound facts are checked before returning the evidence and the lease is
limited to one second from authentication start. This adds native metadata reads;
it is not the planned watch-backed high-throughput object index.

An owned kind Kubernetes v1.37.0 test discovered approximately 9.8 seconds of
TokenReview-only Pod-deletion propagation. With live object guards, the same
strong-deletion fixture withdraws in approximately 0.12 seconds. These are fixture
observations, not fleet latency guarantees. Real signatures, signature tampering,
issuer/audience/namespace checks, unbound refusal, reviewer least privilege,
Pod/ServiceAccount deletion and same-name Pod recreation are qualified. Graceful
termination, partitions, streams and other supported cluster versions still need
deployment qualification. One-second evidence alone does not bound upstream
TokenReview caching; the live metadata guard addresses bound-object withdrawal.

```sh
python3 tools/kubernetes_real_cluster.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview \
  --state-dir /private/owned-kind-qualification
```

The tool is restricted to the named owned kind cluster and private kubeconfig;
it creates unique fixture namespaces/RBAC, removes them, and keeps credentials
out of output and command arguments. It requires Python PyYAML and the cluster's
bundled kubectl; it does not touch production configuration.

Existing workload configurations must add explicit `connection.namespaces` before
upgrade; missing scope fails startup rather than admitting other namespaces.
Kubernetes RBAC authorizes object GET, not a metadata-only permission; the native
connector requests only partial metadata, while its reviewer role must still be
reviewed as Pod/ServiceAccount GET authority.
