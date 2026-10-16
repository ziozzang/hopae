# Subject directory API

<!-- doc-rev: 4 -->

[Documentation](README.md) · [한국어](ko/SUBJECT_DIRECTORY.md)

The subject directory turns the opaque subject references used across the
stack — Hopae user IDs (`u_…`), canonical Human subjects (`human1:<64 hex>`)
and service principals (`s_<48 hex>`) — into what an operator needs to see:
a display name, a masked e-mail address, the principal kind, the providers,
the status (`active`, `disabled`, `deleted`) and creation and activity times.
It also offers a search for subject pickers and a lifecycle feed with a
reconcile snapshot, so that a policy authority (Pumgye) can find bindings
whose subject was disabled or deleted. These are the owner APIs that the
unified console (Hangang ADR 0020) and the Pumgye authorization model
revision (Hangang ADR 0021) assign to Hopae. They are HTTP only, on the admin
listener, beside the rest of the [administration API](ADMIN.md); the Hopae gRPC
surface carries gateway traffic only and has no administrative mirror.

## Prerequisites and configuration

- The management console is enabled (`admin.public_url`, `listen.admin`); see
  [Administration](ADMIN.md). The only further key is
  `admin.directory_privacy` (`standard` by default, or `strict`): the least
  private profile the subject directory and the explain API answer with. A
  request's `privacy_profile` can only make an answer stricter; a request for
  a profile below the floor is answered at the floor, and the answer's
  `privacy_profile` names the profile actually applied.
- Any granted role (`viewer` or `admin`) may call the four reads. A Hangang
  delegated console actor (`admin.hangang_delegation`) may call them with a
  signed assertion over the exact body.
- Human subjects (`human1:`) resolve only when `receipt_issuer.human_receipts`
  is configured: the subject is derived from the receipt issuer reference, the
  store's Human realm and the user ID. Without it a `human1:` reference is
  answered `unknown` with the reason `human_subjects_not_configured`, and the
  lifecycle feed carries `human_subject: null`.
- Service principals resolve from the published service authentication
  profiles: every `api_keys[]` subject of every profile. Subjects minted by a
  remote verifier at authentication time (API relay, Kubernetes TokenReview)
  cannot be enumerated and are answered `unknown` with `not_enumerable`.
- Kubernetes workload principals (`wk2:<64 hex>`) and SPIFFE IDs are
  minted at authentication time as well: they are answered `unknown` with
  `not_enumerable` and `kind: workload`; their lifecycle is in the feed with
  `include_workloads` ([Kubernetes workloads](KUBERNETES_WORKLOAD.md)).

## Behavior

### Request rule

Every read is a `POST` with a JSON body and changes no state other than its
audit record. Because it is a `POST`, a browser request must satisfy the
console's JSON API rule: `content-type: application/json`, the header
`x-hopae-admin-request: 1`, and, when present, `Origin` equal to the console
origin and `sec-fetch-site` equal to `same-origin` or `none`. A request that
does not is `403 csrf_rejected`. The body is at most 64 KiB; unknown fields
are refused. Answers carry `cache-control: no-store`.

### Resolution

`POST /v1/subjects/resolve`

```json
{"ids": ["u_01J...", "human1:9f…", "s_3c…", "u_gone"], "privacy_profile": "standard"}
```

- `ids`: 1 to 100 references, each 1 to 256 bytes. A longer list, an empty
  list or an oversized reference is `400 invalid_request`. Duplicates are
  answered once, in first-occurrence order.
- `privacy_profile`: `standard` (default) returns the display name and the
  primary e-mail address masked to its first character and domain
  (`a***@example.test`); `strict` returns the display name and no e-mail
  address in any form.

Every distinct reference gets one item; a reference that names nothing is not
an error:

| `status` | `reason` | Meaning |
| --- | --- | --- |
| `active` | `null` | A live user or a configured, unexpired service principal |
| `disabled` | `null` | A user disabled by an administrator |
| `disabled` | `credential_expired` | A service principal whose configured credential expired |
| `deleted` | `null` | A tombstone: the user ID is in the append-only reservation ledger but its user row is gone; no personal data is returned |
| `unknown` | `not_found` | A well-formed user ID or Human subject that Hopae never issued |
| `unknown` | `unrecognized` | Not a user ID, `human1:` subject or `s_` principal (a session ID is not a subject) |
| `unknown` | `human_subjects_not_configured` | A `human1:` subject while Human receipts are not configured |
| `unknown` | `index_incomplete` | The Human subject index could not catch up within the request's budget; retry |
| `unknown` | `not_enumerable` | An `s_` principal that is not a configured API-key subject |

Item fields: `id`, `status`, `reason`, `kind` (`human`, `service`,
`workload`), `user_id`, `human_subject`, `display_name`, `email`, `providers`
(the providers of the linked identities), `created_at`, `last_login_at`,
`last_seen_at` (newest session activity), `service_id`, `realm`, `expires_at`
(service credential, milliseconds). Absent values are `null`, never omitted.
The answer also carries `resolved`, `unknown`, `privacy_profile` and
`complete` (`false` when the Human subject index was incomplete).

A Human subject is resolved through an index from subject to reservation-ledger
position that catches up with the ledger incrementally (the ledger is
append-only). Every candidate is re-derived from its ledger row before it is
believed, so a stale or colliding index entry can only cost a miss. The index
holds at most 2,097,152 positions per store and issuer.

### Search

`POST /v1/subjects/search`

```json
{"q": "alice", "kind": "human", "status": "active", "limit": 20, "cursor": null, "privacy_profile": "standard"}
```

- `q`: 1 to 128 characters, no control characters. For `kind: "human"`
  (default) it matches the primary e-mail and username by prefix and the
  display name as a case-insensitive substring, through the users listing of
  the console with its bounded candidate window; an exact user ID or Human
  subject is answered as a resolution. For `kind: "service"` it matches the
  principal name, service, realm or reference as an ASCII case-insensitive
  substring.
- `status`: `active` or `disabled`; `limit`: 1 to 50, default 20; `cursor`: the
  previous answer's `next_cursor` (process-bound, like every console listing
  cursor).

The answer is `{"items": [...], "next_cursor": ..., "privacy_profile": ...}`
with items in the resolution shape.

### Lifecycle feed

`POST /v1/subjects/lifecycle`

```json
{"cursor": "f1.42.1093.e_06GM8SA6R985XVGVXG1P2787G0", "limit": 100}
```

The feed reports, after a durable cursor, the changes Hopae records
atomically with the state they describe:

| `change` | Source | Written |
| --- | --- | --- |
| `created` | The user-ID reservation ledger (schema v10), in creation order | In the transaction that creates the user |
| `disabled` | The `admin.user_disable` outbox event | In the transaction that disables the user, only when the status changes |
| `enabled` | The `admin.user_enable` outbox event | In the transaction that enables the user, only when the status changes |

Each change carries `user_id`, `human_subject`, `at` and `status`: the
subject's status when the page was read (`active`, `disabled`, `deleted`).
Consumers apply `status`, which makes a replayed or reordered page harmless.
Within a page, `created` changes come first. `next_cursor` is the position
after the page and `more` tells whether more is already available. The cursor
`f1.<ledger>.<outbox row>.<event id>` is not a secret and not bound to the
process: a consumer keeps it across restarts of either side. Without a cursor
the feed starts at the oldest retained change.

Hopae has no user deletion or account merge operation. A user row removed by
other means is visible only in the snapshot (`deleted`); `merged` is never
produced. A consumer therefore runs the snapshot periodically as well as the
feed (Hangang ADR 0021: watermark comparison and periodic full reconcile).

`410 cursor_expired` means the cursor's outbox row is no longer the row it
named (pruned by `events.retention_days`/`events.max_rows`, a restored or
replaced store) or its ledger position lies beyond the store's: take a new
snapshot and continue from its watermark.

### Reconcile snapshot

`POST /v1/subjects/lifecycle/snapshot`

```json
{"cursor": null, "limit": 200}
```

Every reserved user ID in ledger order with `user_id`, `human_subject`,
`status` (`active`, `disabled`, `deleted`) and `created_at`; at most 200 per
page, `next_cursor` (`l1.<position>`) until the end. The first page also
carries `watermark`: the feed cursor taken before the first page was read, so
every change after it is in the feed even if the pages miss it. IDs deleted
before schema v10 are not in the ledger and cannot be reported.

## Management API, console and observability

| Endpoint | Body | Answer |
| --- | --- | --- |
| `POST /v1/subjects/resolve` | `ids`, `privacy_profile` | `items`, `resolved`, `unknown`, `complete`, `privacy_profile` |
| `POST /v1/subjects/search` | `q`, `kind`, `status`, `limit`, `cursor`, `privacy_profile` | `items`, `next_cursor`, `privacy_profile` |
| `POST /v1/subjects/lifecycle` | `cursor`, `limit` (1–200, default 100), `include_groups`, `include_workloads` | `changes`, `next_cursor`, `more` |
| `POST /v1/subjects/lifecycle/snapshot` | `cursor`, `limit` (1–200, default 200) | `items`, `next_cursor`, `watermark` |
| `POST /v1/subjects/workloads/snapshot` | `cursor`, `limit` (1–200, default 200) | `items`, `next_cursor`, `watermark` |

Errors: `400 invalid_request` (shape, bounds, unknown field), `400
invalid_cursor`, `403` from the console's authentication and JSON API rule,
`410 cursor_expired`, `429 rate_limited` with `retry-after`, `503
store_unavailable`, `503 audit_unavailable`.

Each actor has a token bucket per read family: resolution 60 requests burst
and 1 per second, search the same, the lifecycle feed and snapshot together
120 burst and 2 per second. The actor is the Hangang delegated actor when the
request is delegated, else the signed-in administrator.

Every answered read writes a required `admin.read` event before the answer
leaves; a read whose record cannot be written is refused with `503
audit_unavailable`. The record names the actor (`attrs.actor`,
`attrs.actor_session`, and for a delegated request `attrs.delegated_actor`),
`attrs.purpose` (`subjects.resolve`, `subjects.search`, `subjects.lifecycle`),
`attrs.endpoint`, `attrs.query_sha256` (SHA-256 of the request body),
`attrs.requested` and `attrs.count`. It never carries the references, the
search text or any personal data. Lifecycle polls that return no change are
not recorded. Refused requests are not reads and are not recorded as such.

## Limitations and compatibility

- Groups, their lifecycle and the signed membership projection are described
  in [groups](GROUPS.md). With `include_groups: true` a resolution attaches up
  to 20 groups to each person and the lifecycle feed also reports
  `group_created`, `group_updated`, `group_deleted`, `member_added` and
  `member_removed` changes (with `group_id`; a group's own change has
  `user_id: null` and the group's state as `status`); without it both answers
  are unchanged.
- With `include_workloads: true` the lifecycle feed also reports Kubernetes
  workload principal changes: `workload_observed` (first authentication by
  an instance), `workload_retired` (ServiceAccount deleted or re-created,
  with `cause` and the `replacement` principal) and `workload_legacy_mapped`
  (a deprecated Pod-bound subject seen as a principal during migration).
  These have `user_id: null`, `status` `active` or `retired` and a `workload`
  object with `principal` (`wk2:`), `subject_ref` (`s_`), `spiffe_id`,
  `cluster`, `namespace`, `service_account`, `service_account_uid`,
  `service` and, when applicable, `cause`, `replacement` and
  `legacy_subject_ref`. Without it the answer is unchanged. Workload
  principals are not in the user snapshot; after `410 cursor_expired` a
  consumer takes `POST /v1/subjects/workloads/snapshot` (`cursor`, `limit`
  1–200, default 200): every recorded principal in registry order, live and
  retired, with `principal`, `subject_ref`, `spiffe_id`, `service`,
  `cluster`, `namespace`, `service_account`, `service_account_uid`,
  `status`, `first_seen_at`, `last_seen_at`, `retired_at`, `cause`,
  `replacement` and up to 64 `legacy_subject_refs`; `next_cursor`
  (`w1.<position>`) until the end; the first page carries `watermark`, the
  feed cursor taken before it, from which the feed (with
  `include_workloads`) continues. The registry (schema 16) is written with
  the events in one transaction and is not pruned by event retention;
  retirement is final. A consumer treats a retired principal's bindings as
  orphaned (Hangang ADR 0021).
- Service principals' lifecycle follows profile publication (the profile
  revision), not this feed.
- The search cursor is bound to the process like every console listing
  cursor; the lifecycle and snapshot cursors are durable.
- A principal the administrator may not view does not exist in Hopae's
  authorization model: every grant holder may resolve every subject.

## Examples, verification and related pages

```sh
curl -sS https://hopae-admin.example.test/v1/subjects/resolve \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -b '__Host-hopae=<redacted>' \
  -d '{"ids":["u_01HZY5W0000000000000000000","s_3c5e…"]}'
```

Scenarios [307](../scenarios/307-subject-resolution-and-search.md) and
[308](../scenarios/308-subject-lifecycle-feed.md) specify the behavior.
Related: [Administration](ADMIN.md), [authentication explain](AUTHENTICATION_EXPLAIN.md),
[Human identity storage](HUMAN_IDENTITY_OWNER.md), [threat model](THREAT_MODEL.md)
(TM-60).
