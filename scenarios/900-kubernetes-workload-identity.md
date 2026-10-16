# S900 — Kubernetes workload identity: a ServiceAccount authenticates offline and keeps access across rollouts

<!-- scenario-status: implemented -->

- Area: security
- Milestone: M7
- ADRs: Hangang ADR 0021 (principal model), Hangang ADR 0022 (Kubernetes-native World package, Decision 5)
- Threat model: TM-70, TM-71, TM-72, TM-73, TM-74
- Gateway contract: service identity response (`x-hopae-principal-kind: workload`, AAL 0, `x-hopae-principal`, `x-hopae-workload-spiffe-id`)

## Goal

A Kubernetes workload presenting a projected ServiceAccount token is
authenticated offline as its ServiceAccount principal (stable across Pods and
rollouts, new on ServiceAccount re-creation), with no Kubernetes API request
on the request path, while forged, misdirected, expired, unbound or revoked
tokens are refused and no Pod fact or token reaches the wire, events or status.

## Preconditions and fixtures

- Owned in-process fixtures only (`src/auth_gateway/workload/fixture.rs`): a
  generated test CA and server certificate, generated RSA 2048 and ECDSA P-256
  signing keys and their JWKS, a token minter producing kube-apiserver-shaped
  projected tokens (`kubernetes.io` namespace, ServiceAccount, Pod, Node), and
  a minimal HTTPS server answering the issuer discovery document, the JWKS
  and metadata-only LIST/WATCH of ServiceAccounts and Pods (resume from
  `resourceVersion`, `410` on demand, request counting, outage switch). No
  real cluster, no external process, no files.
- Profile `kubernetes_workload` with issuer `<fixture>/issuer` (or
  `https://kubernetes.default.svc.cluster.local` with a static JWKS), cluster
  `example-cluster`, trust domain `cluster.example.test`, audience
  `world.hangang.dev/example-cluster`, namespace `blue`, prefix `k8s:`.
- End-to-end cases run the real binary (`m4-admin` plus a `wl` application on
  `workload.example.test` and the profile with `keys.source: "static"` whose
  JWKS is passed by environment reference).

## Main flow

### S900-1 Offline verification publishes the ServiceAccount principal

- Given: a valid RS256 token of `blue/worker` bound to Pod `worker-5d8f-abcde`.
- When: it is presented as `Bearer k8s:<token>`, then a token of another Pod of the same ServiceAccount, then both 50 more times.
- Then: `200`; the subject is `wk2:<64 hex>`, the wire subject its `s_` encoding, the SPIFFE ID `spiffe://cluster.example.test/ns/blue/sa/worker`; the Pod and Node are evidence attributes only; the other Pod has the same principal and wire subject; the JWKS was fetched once and no request reached the API server for the repeated authentications; one `observed` signal per principal.

### S900-2 Claim, signature and binding rules refuse

- Given: tokens with a wrong audience, an extra API-server audience, only the API-server audience, a wrong issuer, expired beyond skew, `nbf`/`iat` in the future, a lifetime above the bound, no `kubernetes.io` claim, no bound object, a Secret binding while only Pods are accepted, a `sub` mismatch, another namespace, a ServiceAccount outside the allowlist, no `iat`, a signature by an unpublished key with a published `kid`, a tampered payload, `alg: none` and `HS256`.
- When: each is presented.
- Then: each is refused (`401`, expiry as expired); the end-to-end case shows no identity header on a refusal; no API request is made.

### S900-3 Key rotation is picked up and `kid` floods are rate-limited

- Given: a verified RSA token, then the issuer adds an ECDSA key.
- When: a token signed by the new key is presented, then twenty tokens with forged `kid`s, then one more after the interval.
- Then: the new key verifies after exactly one refetch; the forged `kid`s cause no further fetch within `kid_miss_min_interval_ms`; one fetch after the interval.

### S900-4 Pinned issuer and CA, allowed JWKS origins, bounded staleness

- Given: discovery naming another issuer; a `jwks_uri` on a foreign origin; another CA; a pinned `jwks_url`; then a key source whose server goes down.
- When: tokens are presented and the key source is refreshed over time.
- Then: `503` for the first three (keys unavailable, nothing fetched from the foreign origin); the pinned URL works; during the outage the last good set is served until `max_stale_seconds`, then the source fails closed and recovers when the server returns.

### S900-5 Watch-backed revocation with bounded staleness

- Given: the revocation watch over `serviceaccounts` and `pods` of `blue`.
- When: the first LIST is pending; the index is ready; the Pod is deleted; the ServiceAccount is re-created with a new UID; the API server goes down.
- Then: `503` until the index is ready; then `200` with no API request per authentication; the deleted Pod's token is refused within 2 s (cache included); the re-created ServiceAccount yields a `retired` signal (`uid_changed`, `replacement` principal) and refuses tokens of the old UID; after `max_staleness_seconds` without confirmation the connector answers `503`.

### S900-6 Migration window for legacy Pod-bound subjects

- Given: `subject: legacy_pod` with `legacy_until_ms` and `legacy_mapping_until_ms` one minute ahead.
- When: a Pod-bound token is presented, then again after the window; then with the default subject and a mapping window.
- Then: the legacy `w_` subject (its `s_` equals the legacy reference) and a `legacy_mapped` signal; after the window `503` (no silent switch); in the default mode the `wk2:` principal with `observed` then `legacy_mapped`.

### S900-7 Static JWKS needs no network

- Given: a profile with `keys.source: static` and the JWKS by reference.
- When: a token is presented.
- Then: `200` with the SPIFFE ID, keys fresh, no network involved.

### S900-8 Lifecycle signals reach the subject lifecycle feed and explain agrees

- Given: the signal pump writing to the store; the real binary after one workload authentication.
- When: the lifecycle feed is read with and without `include_workloads`; the explain API is asked about SPIFFE and `system:serviceaccount` subjects.
- Then: `workload_observed`, `workload_legacy_mapped`, `workload_retired` (with `cause`, `replacement`) appear only with the option, with `user_id: null` and the `workload` identifiers; explain answers `allow/allowed` (200), `deny/workload_namespace_not_allowed` (401), `deny/workload_subject_invalid` (401), `deny/network_denied` (401) with `connectors: ["kubernetes_workload"]`, and the live path agrees.

## Alternative flows

### S900-9 Routing, status and republication through the compiled runtime

- Given: a profile with local API keys and the workload connector.
- When: prefixed and unprefixed credentials from inside and outside the networks; connector status; explain verdicts; republication with identical material; a profile with both Kubernetes connectors.
- Then: only prefixed credentials reach the workload verifier; network denial first; local keys unaffected; status shows a `kubernetes-workload` row with fresh keys and no material or reference name; explain verdicts as in S900-8 plus `NoProfile`; the resumed runtime keeps the connector; the combined profile is refused.

### S900-11 An existing TokenReview profile must declare its subject

- Given: a root configuration whose `kubernetes_tokenreview` profile has no `subject`.
- When: it is loaded; then with `legacy_pod` alone; with `legacy_pod`, `legacy_until_ms` and `legacy_mapping_until_ms`; with `service_account`; and a new `kubernetes_workload` profile without `subject`.
- Then: the first load fails with `kubernetes_tokenreview.subject is required …`, naming `legacy_pod` and the migration section; `legacy_pod` without a window fails on `legacy_until_ms`; the declared forms load; the new offline profile defaults to `service_account`.

### S900-12 The workload snapshot recovers principals after a lost cursor

- Given: lifecycle signals for a principal (observed, legacy mapping, retired with a replacement), its replacement, and a late observation of the retired one; then outbox retention removes the events; and the real binary after one authentication.
- When: `POST /v1/subjects/workloads/snapshot` is read, paged by its cursor, and an un-retire is attempted in SQL; a foreign cursor is presented.
- Then: both principals are listed in registry order, the retired one with `cause`, `replacement` and its legacy subject; the late observation did not revive it and the schema refuses un-retiring; the binary's snapshot contains the active principal and a feed `watermark`; a foreign cursor is `400`.

### S900-10 The response carries the principal and SPIFFE ID, never Pod facts

- Given: an authenticated workload.
- When: the service identity response is rendered.
- Then: the forwarded user header is the `s_` wire subject, `x-hopae-principal-kind: workload`, `x-hopae-aal: 0`, `x-hopae-principal: wk2:…`, `x-hopae-workload-spiffe-id`; no Pod name or UID appears.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S900-2 | yes: tokens for another audience (including the API server) or past their lifetime are refused; a valid token is a bearer credential bounded by its `exp` (TM-70) |
| Tampering | S900-2 | yes |
| Race / timing | S900-5 | yes: revocation within the staleness bound; a stale index fails closed |
| Resource exhaustion | S900-3 | yes: forged `kid` floods are rate-limited; cache, index and signal queue are bounded (S900-A1) |
| Confused deputy | S900-2 | yes: an API-server token cannot authenticate here; the audience must be dedicated (S900-A1) |
| Spoofed or duplicated headers | S900-10 | yes: identity headers are outputs of verification only |
| Downgrade | S900-2 | yes: `none`, HMAC and legacy unbound tokens are refused; the legacy subject needs an expiring window (S900-6) |
| Enumeration | — | no: refusals are uniform and carry no reason to the caller; feed and explain reads are granted and audited (TM-60, TM-61) |

### S900-A1 Unsafe configurations are refused

- Given: profiles with the issuer or an API-server audience as audience, an HTTP issuer, an invalid trust domain, no or duplicate namespaces, a ServiceAccount outside the namespaces, a short lifetime bound, a large skew, `legacy_pod` without a window, an invalid prefix, an oversized cache, a non-watch revocation mode, a watch without ServiceAccounts or without a credential, keys without a source reference or CA, a too-small `kid` interval, a relative token file, and inline material.
- When: each is validated.
- Then: each is refused before any connector is built.

## Observability expectations

- Log: a warning per failed key refresh or revocation list (service, reason); a deprecation warning when a TokenReview profile is compiled; never tokens or bodies.
- Audit: required `workload.principal_observed`, `workload.principal_retired`, `workload.legacy_subject_mapped`; diagnostic `workload.keys_rotated`, `workload.revocation_stale`.
- Metrics: `hopae_workload_authentications_total`, `hopae_workload_cache_total`, `hopae_workload_cache_entries`, `hopae_workload_jwks_fetch_total`, `hopae_workload_jwks_keys`, `hopae_workload_revocation_events_total`, `hopae_workload_revocation_staleness_ms`, `hopae_workload_signals_total`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S900-1 | `s900_1_offline_verification_publishes_service_account_principal` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-1 | `s900_1_offline_workload_principal_survives_rollout` | `tests/scenarios/s900_kubernetes_workload.rs` | integration | passing |
| S900-2 | `s900_2_claims_signature_and_binding_rules_refuse` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-2 | `s900_2_refusals_carry_no_identity` | `tests/scenarios/s900_kubernetes_workload.rs` | integration | passing |
| S900-3 | `s900_3_rotation_kid_miss_refetch_is_rate_limited` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-4 | `s900_4_pinned_issuer_ca_and_bounded_staleness` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-5 | `s900_5_watch_revocation_with_bounded_staleness` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-6 | `s900_6_legacy_pod_subject_window_and_mapping_signals` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-7 | `s900_7_static_jwks_needs_no_network` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-8 | `s900_8_signals_become_lifecycle_feed_changes` | `src/auth_gateway/workload/events.rs` | unit | passing |
| S900-8 | `s900_8_lifecycle_feed_and_explain` | `tests/scenarios/s900_kubernetes_workload.rs` | integration | passing |
| S900-9 | `s900_9_runtime_routing_status_and_explain` | `src/auth_gateway/workload/tests.rs` | unit | passing |
| S900-10 | `s900_10_workload_response_carries_principal_and_spiffe_id` | `src/gateway/hangang/service_identity.rs` | unit | passing |
| S900-11 | `s900_11_tokenreview_profile_without_subject_fails_loud_at_load` | `src/config/mod.rs` | unit | passing |
| S900-12 | `s900_12_registry_snapshot_survives_outbox_retention` | `src/auth_gateway/workload/events.rs` | unit | passing |
| S900-A1 | `s900_a1_configuration_refuses_unsafe_profiles` | `src/auth_gateway/workload/tests.rs` | unit | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | not run | Real-cluster qualification (kube-apiserver discovery/JWKS, rotation, watch) is a separate gate; no cluster was touched. |

## Open questions

- Hangang carriage of X.509-SVID callers onto the same principal (contract in [Kubernetes workloads](../docs/KUBERNETES_WORKLOAD.md#spiffe-alignment-and-hangang-workload-mtls)).
- Replacement of the per-profile watch by World controller tombstones (ADR 0022 Decision 3).

## 한국어 요약

projected ServiceAccount 토큰을 오프라인(JWKS)으로 검증해 Pod가 아닌 ServiceAccount 주체(`wk2:`, SPIFFE ID)로 인증하며, 롤아웃 뒤에도 주체가 유지되고 요청 경로에서 Kubernetes API를 호출하지 않습니다. 잘못된 audience·issuer·서명·만료·바인딩 없는 토큰, 위조 `kid` 폭주, 지연된 폐기 인덱스는 거절되거나 실패 시 닫힙니다.
