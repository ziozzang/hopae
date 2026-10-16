# Kubernetes workload authentication

<!-- doc-rev: 7 -->

[Documentation](README.md) · [한국어](ko/KUBERNETES_WORKLOAD.md)

Hopae authenticates Kubernetes workloads by their projected ServiceAccount
tokens. Since Hangang ADR 0022 (P0) the default connector is
`kubernetes_workload`: tokens are verified **offline** against the cluster's
OIDC discovery document and JWKS, the authenticated principal is the
**ServiceAccount** (never the Pod), and no Kubernetes API request is made on
the request path. The older `kubernetes_tokenreview` connector, which calls
TokenReview and reads the ServiceAccount and Pod on every uncached request, is
kept as a **deprecated** fallback and is off unless a profile names it
([below](#deprecated-tokenreview-fallback)).

Implementation: `auth_gateway::workload` (offline connector, identity, key
source, revocation watch, lifecycle signals) and `auth_gateway::kubernetes`
(fallback). Real-cluster qualification of the offline connector is still a
gate (see [Limitations](#limitations-and-deferred-work)).

## Workload identity model

| Identifier | Form | Scope | Used for |
| --- | --- | --- | --- |
| Principal | `wk2:<64 hex>` = SHA-256 over the domain `hopae:kubernetes:workload-principal:v2`, then the length-prefixed issuer, cluster ID, namespace, ServiceAccount name and ServiceAccount **UID** | One incarnation of one ServiceAccount | Hangang ADR 0021 `PrincipalRef` of kind `workload`; lifecycle feed; response header `x-hopae-principal` |
| SPIFFE ID | `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>` | The ServiceAccount name in a trust domain (no UID) | Canonical workload name shared with Hangang workload mTLS; response header `x-hopae-workload-spiffe-id`; explain subjects |
| Wire subject | `s_<48 hex>`: the existing stable-subject encoding of the principal (kind workload, issuer, cluster realm) | As the principal | The forwarded user header, Pumgye `workload_users`, receipts; parsers in Hangang and Pumgye are unchanged |
| Audit attributes | Pod name/UID, bound Secret name/UID, Node name | One credential | Evidence and audit only; never part of the principal, never on the wire |

- **Rollouts keep access.** Every Pod of a ServiceAccount, in every replica
  and every rollout, authenticates as the same principal and wire subject.
- **Re-creation policy.** Deleting a ServiceAccount and creating one with the
  same name gives it a new UID and therefore a new principal and wire subject.
  Grants bound to the old principal do not transfer; Hopae reports the old one
  as retired (`workload.principal_retired`, cause `uid_changed`, with the
  `replacement` principal) when the revocation watch observes it. Intent that
  should survive re-creation is expressed by name (`AccessBinding` subjects
  `ServiceAccount{namespace,name}` resolved by the World controller, ADR 0022),
  which trusts whoever may re-create the ServiceAccount in that namespace.
- The principal kind is `workload` with AAL 0; no machine credential satisfies
  a human step-up rule.

## Offline verification (`kubernetes_workload`)

A profile carries at most one of `kubernetes_workload` and
`kubernetes_tokenreview`. Example with discovery, a dedicated audience and the
revocation watch (all material by reference):

```json
{
  "service_id": "orders", "host": "orders.example.test", "ports": [443],
  "realm": "example-cluster",
  "kubernetes_workload": {
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "cluster_id": "example-cluster",
    "trust_domain": "cluster.example.test",
    "audience": "world.hangang.dev/example-cluster",
    "namespaces": ["blue"],
    "service_accounts": ["blue/worker"],
    "keys": {
      "source": "discovery",
      "jwks_origins": ["https://10.0.0.1:6443"],
      "ca_pem_env": "HOPAE_KUBERNETES_CA_PEM",
      "token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    },
    "revocation": {
      "mode": "watch",
      "api_origin": "https://kubernetes.default.svc/",
      "token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    },
    "token_prefix": "k8s:"
  }
}
```

| Field | Default | Rule |
| --- | --- | --- |
| `issuer` | required | HTTPS URL, at most 256 bytes; the token `iss` and the discovery `issuer` must equal it byte for byte |
| `cluster_id` | required | Must equal the profile `realm`; part of the principal |
| `trust_domain` | required | SPIFFE trust domain (lowercase letters, digits, `.`, `-`, `_`) |
| `audience` | required | The audience this service requires. Never the issuer or an API-server audience (`api`, `kubernetes`, `https://kubernetes.default.svc[.cluster.local]`): a token for the API server must not be accepted here |
| `exclusive_audience` | `true` | The token must carry no other audience, so a token minted for Hopae is not also valid at another service |
| `namespaces` | required | 1–128 distinct namespaces |
| `service_accounts` | all | Optional `namespace/name` allowlist (at most 1,024, inside `namespaces`) |
| `bound_objects` | `["pod"]` | `pod` and/or `secret`: which bound-object claims are accepted. Tokens without a `kubernetes.io` claim (legacy Secret tokens) and projected tokens bound to nothing are refused |
| `keys.source` | required | `discovery`, `jwks_url` or `static` |
| `keys.discovery_url` | `<issuer>/.well-known/openid-configuration` | Discovery only |
| `keys.jwks_url` | — | Required for `jwks_url`; with `discovery` it pins the advertised `jwks_uri` |
| `keys.jwks_origins` | issuer and discovery origins | Further origins an advertised `jwks_uri` may use (at most 8). Kubernetes usually advertises the API server's address, not the issuer host |
| `keys.jwks_env` | — | `static`: reference to a JWKS document (for hosts that cannot reach the cluster; rotate by republishing) |
| `keys.ca_pem_env` | — | Required for network sources; only these roots are trusted |
| `keys.token_env` / `keys.token_file` | none | Optional bearer for discovery/JWKS; a file is re-read per fetch (projected tokens rotate) |
| `keys.refresh_seconds` | 300 | 30–3,600: background refresh interval |
| `keys.max_stale_seconds` | 3,600 | `refresh_seconds`–86,400: last-known-good bound; beyond it the connector answers 503 |
| `keys.kid_miss_min_interval_ms` | 10,000 | 1,000–300,000: at most one refetch for an unknown `kid` per interval |
| `keys.timeout_ms` | 2,000 | 100–10,000 per fetch |
| `clock_skew_seconds` | 30 | 0–300, applied to `exp`, `nbf` and `iat` |
| `max_token_lifetime_seconds` | 86,400 | 600–604,800: `exp − iat` above it is refused |
| `cache.ttl_ms` / `cache.max_entries` | 10,000 / 10,000 | 0–60,000 ms / 0–262,144; 0 disables the positive cache |
| `revocation` | none | Optional watch, [below](#revocation-watch) |
| `subject` | `service_account` | `legacy_pod` only for migration, [below](#migration-from-pod-bound-subjects) |
| `legacy_until_ms`, `legacy_mapping_until_ms` | none | Migration windows (Unix milliseconds) |
| `token_prefix` | required | 2–32 characters ending in `:`; routes `Bearer <prefix><token>` to this connector |

Unknown fields are refused; secret material is never part of the
configuration (`ca_pem`, inline JWKS or tokens are rejected as unknown keys).

### Verification order

1. The credential carries the profile's prefix (otherwise it never reaches
   this connector; other connectors keep their routing), is at most 8,192
   bytes and passes the profile's network predicate.
2. Positive cache lookup by SHA-256 of the token (the token is never stored).
   A hit skips only the signature: scope and revocation are re-checked.
3. Header: `alg` in RS256/RS384/RS512/ES256/ES384 (never `none` or HMAC), no
   `crit`; the key is chosen by `kid`. An unknown `kid` triggers at most one
   refetch per `kid_miss_min_interval_ms` (single flight); a forged-`kid` flood
   cannot turn into requests to the API server.
4. Signature with the selected key.
5. Claims of the verified payload: `iss`; `aud` (required, exclusive by
   default); `exp` and `iat` required, `nbf` optional, each with
   `clock_skew_seconds`; `exp − iat ≤ max_token_lifetime_seconds`;
   `kubernetes.io.namespace`, `serviceaccount{name,uid}` and a configured
   bound object; `sub = system:serviceaccount:<ns>:<sa>`; namespace and
   ServiceAccount allowlists. A `warnafter` in the past (extended-expiry
   tokens) is counted, not refused.
6. Revocation index (when configured), then the profile's Lua eligibility
   rule, then evidence: kind `workload`, AAL 0, service-scoped, lease at most
   one second and never beyond `exp` plus skew.

Refusals are `401` (credential) or `503` (keys unavailable, revocation index
stale, legacy window over); the caller never learns which rule refused.

### Keys: rotation, outage and pinning

Discovery must name exactly the configured issuer; the advertised `jwks_uri`
must be HTTPS on an allowed origin (or equal the pinned `jwks_url`). Every
fetch trusts only `ca_pem_env`, uses no proxy and follows no redirect; bodies
are limited to 64 KiB and the set to 64 asymmetric signature keys (symmetric
and encryption keys are dropped). A background task refreshes the set every
`refresh_seconds`; failures back off (1 s doubling to 32 s, at most the
refresh interval) and keep serving the last good set while it is younger than
`max_stale_seconds`. When the cluster rotates its signing key, the new `kid`
is picked up by the next refresh or immediately by the first token that names
it. A key removed from the JWKS stops verifying after the next refresh.

### The hot path

With the positive cache, the key cache and the in-memory revocation index,
an authentication performs **no network request**: no TokenReview, no
ServiceAccount or Pod GET. Scenario 900-1 checks this by counting the fixture
API server's requests across repeated authentications. Network traffic is
limited to the background key refresh, rate-limited `kid` misses and the
watch streams.

## Revocation watch

Offline verification cannot see that the object a token is bound to was
deleted. With `revocation.mode: "watch"` the connector keeps a metadata-only
index of the ServiceAccounts (and, with `resources` containing `pods`, the
Pods) of every allowed namespace through LIST and WATCH
(`PartialObjectMetadata`, bookmarks, `resourceVersion` resume, relist on
`410 Gone`). On the request path only this index is read:

| Index state | Answer |
| --- | --- |
| ServiceAccount absent, or present with another UID (re-created) | `401` |
| Pod absent, present with another UID, or terminating (`deletionTimestamp` set) | `401` |
| Index not yet listed, older than `max_staleness_seconds`, or over `max_objects` | `503` (fail closed) |

Freshness is confirmed by a completed LIST, an event, a bookmark or a
(re-)established watch; each watch asks the server to end after a third of
the staleness bound (1–290 s) and has a client deadline 5 s later, so a
silent or stalled stream is renewed well inside the bound. LIST pages are
500 objects and at most 4 MiB; watch lines at most 64 KiB. A positive-cache
hit is subject to the same check, and deletions observed by the watch also
evict cached entries. `max_staleness_seconds` is 5–600 (default 60);
`max_objects` 1–1,000,000 (default 200,000; an overflow keeps failing closed
until the profile is republished with a larger bound). The watch credential
(`token_env` or a re-read `token_file`) needs only:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: hopae-workload-revocation, namespace: blue}
rules:
- apiGroups: [""]
  resources: ["serviceaccounts", "pods"]
  verbs: ["list", "watch"]
```

Without the watch, a token stays valid until its `exp` after its
ServiceAccount or Pod is deleted; keep token lifetimes short
(`expirationSeconds`, `max_token_lifetime_seconds`). ADR 0022's controller
tombstones (signed revocation deltas) are the planned replacement of this
per-authority watch.

## Migration from Pod-bound subjects

Before ADR 0022, `kubernetes_tokenreview` published a subject hashed over the
namespace, ServiceAccount name/UID **and Pod name/UID** (`w_…`, wire subject
`s_…`), so a grant died with its Pod. New `kubernetes_workload` profiles
publish the ServiceAccount principal by default. An existing
`kubernetes_tokenreview` profile must **declare** `subject`: without it the
configuration load, the preflight check and a profile publication fail with
`kubernetes_tokenreview.subject is required since Hangang ADR 0022 …` and a
pointer to this section, so an upgrade never changes a published subject
silently. Operator migration:

0. **Declare the current behaviour.** Before (or with) the upgrade, add
   `"subject": "legacy_pod"` with `"legacy_until_ms"` (the end of the
   migration window) and `"legacy_mapping_until_ms"` to every existing
   TokenReview profile. Callers keep their Pod-bound subjects; nothing else
   changes.
1. **Observe mappings.** Set `legacy_mapping_until_ms` (for example two weeks
   ahead). Each Pod-bound legacy subject that authenticates is reported once
   per process as `workload.legacy_subject_mapped` with `legacy_subject_ref`
   and the new `principal`/`subject_ref`.
2. **Reconcile in Pumgye.** Consume the lifecycle feed with
   `include_workloads: true`; the ADR 0021 converter maps a Pod-bound grant to
   the ServiceAccount principal only after an administrator confirms the
   namespace/ServiceAccount, otherwise it stays a deprecated legacy entry.
3. **Re-grant.** Create the bindings on the ServiceAccount principals (the
   Pumgye v2 converter consumes the `legacy_subject_mapped` events). While
   Pumgye still evaluates Pod-bound grants, `legacy_pod` keeps publishing the
   legacy subject (Pod-bound tokens only). At `legacy_until_ms` the connector
   refuses with `503`; it never silently switches subjects.
4. **Cut over.** Set `"subject": "service_account"`, remove
   `legacy_until_ms`, keep or drop the mapping window, then retire the
   Pod-bound grants.

## SPIFFE alignment and Hangang workload mTLS

The SPIFFE ID is the workload name shared with Hangang's dedicated workload
mTLS listeners (`allowed_uri_sans`). Hopae does not terminate those
connections and receives no client certificate on the existing HTTP/HOP1
path, so X.509-SVID callers are authenticated by Hangang. Contract for one
identity model with two credential formats:

- Hangang verifies the X.509-SVID (exactly one canonical SPIFFE URI SAN,
  configured CA) and maps `spiffe://<td>/ns/<ns>/sa/<sa>` to the same
  workload name Hopae reports in `x-hopae-workload-spiffe-id`; route policies
  and Pumgye bindings that name a ServiceAccount by SPIFFE ID or
  `ServiceAccount{namespace,name}` match both credential formats.
- An SVID carries no UID, so it cannot produce the UID-pinned `wk2:`
  principal by itself. Until the World controller distributes the current
  ServiceAccount UID (ADR 0022 Decision 3), bindings pinned to a `wk2:`
  principal apply to token callers only; name-based bindings apply to both.
- The trust domain must be configured identically in Hopae
  (`trust_domain`) and Hangang (`allowed_uri_sans`).

## Lifecycle events and the subject lifecycle feed

| Event | Kind | When | Attributes |
| --- | --- | --- | --- |
| `workload.principal_observed` | required | First authentication of a principal by this process (bounded memory: a forgotten principal is reported again) | `service`, `principal`, `subject_ref`, `spiffe_id`, `cluster`, `namespace`, `service_account`, `service_account_uid`, `status: active` |
| `workload.principal_retired` | required | The revocation watch saw the ServiceAccount deleted (`cause: deleted`) or re-created (`cause: uid_changed`, `replacement`) | as above, `cause`, `replacement`, `status: retired` |
| `workload.legacy_subject_mapped` | required | During `legacy_mapping_until_ms`, a Pod-bound legacy subject authenticated as a principal | as above, `legacy_subject_ref` |
| `workload.keys_rotated` | diagnostic | The issuer's key set changed | `service`, `keys_added`, `keys_removed` |
| `workload.revocation_stale` | diagnostic | The revocation index became stale (`stale: true`, outcome failure) or current again | `service`, `stale` |

Signals travel through a bounded queue (4,096) to one writer per process;
a full queue drops and counts (`hopae_workload_signals_total{result="dropped"}`),
and the consumer's periodic reconcile catches up. `POST
/v1/subjects/lifecycle` with `include_workloads: true` reports these as
`workload_observed`, `workload_retired` and `workload_legacy_mapped` changes
with `user_id: null` and a `workload` object; without the option the feed is
unchanged ([subject directory](SUBJECT_DIRECTORY.md)). No event carries a token,
Pod name or Pod UID.

## Status, metrics and explain

`GET /v1/status` lists a `kubernetes-workload` connector per profile with
`circuit` (`closed` when keys are fresh and the revocation index is current)
and a `workload` object: issuer, cluster, trust domain, audience, subject
mode, key source state (`source`, `keys`, `age_ms`, `fresh`,
`consecutive_failures`, `last_error`), revocation state (`ready`,
`staleness_ms`, `max_staleness_ms`, `objects`, `overflow`) and cache entries.
No key material, credential or reference name is shown.

| Counter or gauge | Labels |
| --- | --- |
| `hopae_workload_authentications_total` | `service`, `verification` (`offline_jwks`, `tokenreview`), `result` (`authenticated`, `denied`, `warning`), `reason` |
| `hopae_workload_cache_total`, `hopae_workload_cache_entries` | `service`, `result` (`hit`, `miss`) |
| `hopae_workload_jwks_fetch_total`, `hopae_workload_jwks_keys` | `service`, `result` (`ok`, `rotated`, `kid_miss_rate_limited` or a failure reason) |
| `hopae_workload_revocation_events_total`, `hopae_workload_revocation_staleness_ms` | `service`, `resource`, `event` |
| `hopae_workload_signals_total` | `kind`, `result` (`queued`, `dropped`, `recorded`, `failed`) |

The [authentication explain API](AUTHENTICATION_EXPLAIN.md) accepts a
workload subject as a SPIFFE ID of the profile's trust domain or as
`system:serviceaccount:<ns>:<sa>` and evaluates, in the live order, the
profile, network predicate, namespace and ServiceAccount allowlists, key
freshness, the revocation index and the migration window. Token-dependent
checks are reported as `workload_token_not_simulated`.

## Deployment notes

- In-cluster, the discovery endpoints usually need a bearer: bind
  `system:service-account-issuer-discovery` to Hopae's ServiceAccount and use
  `keys.token_file` with its projected token, or publish the issuer's
  discovery anonymously. `keys.ca_pem_env` holds the cluster CA.
- Workloads request a dedicated token:

```yaml
volumes:
- name: hopae-token
  projected:
    sources:
    - serviceAccountToken:
        audience: world.hangang.dev/example-cluster
        expirationSeconds: 600
        path: token
```

- Out of cluster (the operating host), use `keys.source: "static"` with the
  JWKS from `kubectl get --raw /openid/v1/jwks` and republish on key rotation,
  or `jwks_url` reachable through the API server address.

## Deprecated TokenReview fallback

**Deprecated** (Hangang ADR 0022): use `kubernetes_workload` unless the
issuer's keys cannot be reached. Native library: `auth_gateway::kubernetes::Connector`.
It authenticates Pod-bound ServiceAccount JWTs through a fixed trusted
Kubernetes TokenReview API. Reference-only root/profile configuration, HTTP/HOP1
dispatch and console overview are integrated. Compiling a profile logs a
deprecation warning. Owned actual API qualification is recorded below.

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
It is the ServiceAccount principal of the [identity model](#workload-identity-model)
(issuer, cluster, namespace, ServiceAccount name and UID); the Pod name/UID is an
audit attribute. Optional `trust_domain` adds the SPIFFE ID. `subject` is
required (`service_account`, or `legacy_pod` with a mandatory
`legacy_until_ms`, [migration](#migration-from-pod-bound-subjects)).
Evidence is service-scoped, expires at the earlier of token expiry
and one second after authentication start, and contains no credential or Pod
labels. The native caller supplies trusted time. Without `cache_ttl_ms` there is
no result cache: every invocation contacts TokenReview, using pooled connections
and at most 64 outstanding requests. `cache_ttl_ms` (at most 10,000) keeps a
positive result keyed by the token digest for that long, bounding the API load
at the cost of that revocation delay. Three source failures open the cancellation-safe endpoint circuit for
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
Hopae lease does not eliminate that API-side window. Live object checks below
provide early bound-object withdrawal (skipped on a positive-cache hit).

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
    "token_prefix": "k8s:",
    "subject": "service_account",
    "trust_domain": "cluster.example.test",
    "cache_ttl_ms": 0
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
subject with AAL 0, plus `x-hopae-principal` and (with a trust domain)
`x-hopae-workload-spiffe-id` for both workload connectors; no machine proof
satisfies a human step-up rule. Hangang's
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


## Native evidence lifetime

HTTP and HOP1 machine responses export `x-hopae-evidence-ttl-ms`, the remaining
verified evidence lifetime at response construction, capped at 1000 ms. Expired
evidence yields 503 without identity headers. This is authenticated response
metadata, not a decision cache, signed receipt or client-provided authentication.
Hangang anchors it to the start of its native exchange so network/processing time
cannot extend the lease. Workload and service streams must stop at that deadline
unless a future authenticated renewal/subscription replaces the evidence.

This initial enforcement closes long machine streams at most one second after
authentication (plus the retirement poll scheduling interval). Hangang now provides opt-in native reauthentication via
`auth.renew_native_evidence`; it requires explicit usable TTL and unchanged
subject/kind/AAL/service, and refuses failed or late renewals. Targeted
credential-revocation subscriptions and sustained real-cluster source
availability are not implemented. Existing
production images have not been switched by the lifetime qualification; do not
claim this completes long-lived workload authentication.

## Owned verifier readiness files

The local mock API publishes its ephemeral port through an exclusive0600
same-directory temporary file, flush/fsync and atomic replacement. Readers cannot
observe the final `ready` name while its contents are empty/partial. Both native
RPC and HTTP/HOP1 fixtures additionally require canonical ASCII decimal1..65535
before constructing an endpoint; empty content cannot silently become the default
HTTPS port443. This is fixture IPC hardening, not a change to production API
origin semantics, credential validation, authentication retries or original1s
source budgets.

A deterministic scheduling gate reproduced the old create-before-write window,
and the actual production config checker accepted the resulting empty-port origin.
This establishes a concrete fixture race mechanism. Historical Workload first-Issue
refusals did not capture their ready-file contents, so their cause remains
unproven; an isolated passing test is not a causal diagnosis.

Run `python3 -m unittest discover -s tools -p test_owned_kubernetes_verifier.py -v`
for publication, replacement, failure cleanup and invalid-port regressions. Shared
Rust fixture parsing also rejects empty, zero, leading-zero, overflow, whitespace,
signs, non-ASCII and path-like input before URL construction. The owned TokenReview
API remains a protocol fixture and does not validate real Kubernetes JWT signatures.


## Limitations and deferred work

- Not yet qualified on a real cluster: the offline connector, its discovery
  against kube-apiserver and the watch were exercised only against owned
  in-process fixtures (generated RSA/ECDSA keys, a JWKS/discovery and
  LIST/WATCH server). The TokenReview fallback keeps its earlier owned-kind
  qualification.
- Controller-pushed tombstones and signed snapshots (ADR 0022 Decision 3)
  are not implemented; the per-profile watch is the interim revocation source
  and needs its own narrowly scoped credential.
- X.509-SVID callers are authenticated by Hangang, not Hopae (contract above).
- Only one issuer per profile; issuer migration (several
  `--service-account-issuer` values) needs two profiles or a republish.
- The ADR 0021 `wk2:` principal is reported beside, not instead of, the wire
  subject `s_…`; Pumgye v2 consumes `wk2:` from the header and the lifecycle
  feed.
