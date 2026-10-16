# Groups and the membership projection

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/GROUPS.md)

Hopae owns groups (Hangang ADR 0021): local groups that administrators
manage, groups synced from an LDAP directory (`memberOf` or a group search)
and groups taken from an OpenID Connect `groups` claim. Each group has an
opaque, never reused reference `grp1:<26 crockford>` (a GroupRef). Pumgye
binds roles to GroupRefs and learns who is in which group only from Hopae's
**signed membership projection**; it never reads LDAP or tokens and never
trusts group names from request headers. The decision record is
[ADR-0018](adr/0018-groups-and-membership-projection.md).

## Prerequisites and configuration

Groups need schema version 14 (migration `0014_groups`, applied at start).
Local groups need nothing else. Provider sync is configured per provider and
the projection needs a signing key:

```json
{
  "groups": {
    "max_groups_per_user": 256,
    "change_retention_days": 30,
    "maintenance_interval_secs": 300,
    "stale_group_days": 30,
    "gateway_header": false,
    "projection": {
      "issuer_ref": "hopae-groups", "key_epoch": 1,
      "public_key": "<base64 Ed25519 public key>",
      "seed_env": "HOPAE_GROUPS_PROJECTION_SEED", "audience": "pumgye"
    }
  },
  "providers": [
    {"provider_id": "corp", "kind": "oidc", "groups": {
      "claim": "groups", "include": "^eng-", "exclude": "-legacy$",
      "rewrite": {"pattern": "^eng-(.+)$", "replacement": "Engineering $1"},
      "max_groups": 100, "removal_grace_secs": 0}},
    {"provider_id": "directory", "kind": "ldap", "ldap": {"…": "…"}, "groups": {
      "ldap": {"mode": "member_of", "member_of_attribute": "memberOf"},
      "include": "ou=apps,dc=example,dc=test$",
      "sync_interval_secs": 3600, "sync_batch": 200}}
  ]
}
```

Every key, its default and its bounds are in the
[configuration reference](CONFIG.md#groups). A provider without a `groups`
section syncs nothing. The projection seed is a base64 32-byte Ed25519 seed
in the named environment variable; it must match `public_key` and must not be
the receipt issuer's key, or Hopae refuses to start.

## Behavior

### Model

| Object | Fields |
| --- | --- |
| Group | `group_id` (GroupRef), `source` (`local`, `ldap`, `oidc`), `provider_id` (null for local), `key` (stable source key: the local key, the normalized LDAP DN, or the OIDC claim value), `name`, `description`, `state` (`active`, `deleted`), `revision`, `members`, `created_at`, `updated_at`, `last_seen_at` (last sync report), `deleted_at` |
| Membership | person (Hopae user ID, exported as the `human1:` subject), group, `source`, `provider_id`, `first_seen_at`, `last_seen_at`, `expires_at` (local only), `removal_pending_at` (provider only), `added_by` and `reason` (local only) |

Times are Unix seconds. A deleted group stays as a tombstone so that its
reference keeps resolving; a new group never takes an old reference, even
with the same key. Nested groups are out of scope: a group contains people
only.

### Source of truth

- A provider group and its memberships are written only by that provider's
  sync. An administrator write to one answers `409 group_not_local`.
- A local group and its memberships are written only by administrators.
- A person's total group count is bounded by `groups.max_groups_per_user`.

### Provider sync

A provider assertion is the person's **complete** group set from that
provider. It is applied in one store transaction:

1. Each source value goes through the provider's rules: invalid values
   (empty, over 512 bytes, control characters) are dropped; `include` keeps
   only matching keys, then `exclude` drops matching keys; `rewrite` maps the
   display name (the key never changes); duplicates collapse.
2. More than `max_groups` groups after filtering, more than 4,096 raw values,
   or a result above `groups.max_groups_per_user`, **refuses the whole
   assertion**: nothing changes and a `group.sync_refused` diagnostic event is
   written. A truncated set would remove memberships the provider still
   asserts.
3. Unknown groups are created; a changed name is a rename (`group.updated`).
4. New memberships are added. Memberships no longer asserted are removed at
   once when `removal_grace_secs` is 0 (the default); otherwise they are
   marked `removal_pending_at`, stay effective during the grace, and are
   removed by the next sync or maintenance pass after it, unless asserted
   again.

Sources:

- **OIDC**: the claim at `groups.claim` (default `groups`, a dotted path such
  as `realm_access.roles`) in the ID token, else in the user-info response
  (whose `sub` was checked). An absent claim, or one that is not an array of
  strings, is not an assertion: memberships stay as they are. An empty array
  asserts "no groups". Groups never enter the stored identity claims.
- **LDAP** at sign-in: `member_of` mode reads the person entry's
  `memberOf` (or `member_of_attribute`) in the same search that finds the
  entry; `search` mode searches `object_class` entries under
  `search_base_dn` (default the provider's `base_dn`) whose
  `member_attribute` equals the person's DN, naming each group by
  `name_attribute`. Both run with the service bind before the person's bind;
  the result is applied only after the password is verified. A group key is
  the DN with ASCII letters lower-cased and spaces around separators
  removed; its name is the first RDN value (or `name_attribute`). An
  incomplete answer (size limit, referral, error) is not an assertion.
- **LDAP periodic sync** (`sync_interval_secs`): each maintenance pass
  refreshes up to `sync_batch` linked identities of the provider, looked up
  by their immutable subject attribute with the service bind. A full cycle
  starts at most once per interval. A person no longer in the directory
  asserts "no groups". A directory that does not answer stops the step and
  keeps every membership (`last_error` is recorded).

A sync never blocks a sign-in: a failed or refused sync keeps the previous
memberships. Memberships therefore reflect the provider as of the last
successful sync; while a directory is unreachable they are not withdrawn.

### Maintenance

Every `maintenance_interval_secs` Hopae removes expired local memberships,
provider memberships past their grace, memberships whose provider row was
deleted, deletes provider groups with no member that no sync reported for
`stale_group_days` (or whose provider is gone), prunes projection journal rows
older than `change_retention_days` (the newest row is always kept), and runs
the periodic LDAP sync step. Reads hide an expired local membership even
before the pass removes it.

### Gateway headers (default off)

With `groups.gateway_header: true`, Hopae mirrors a person's group
references (at most 32, in lexical order) into `users.groups`, so the
[gateway contract](GATEWAY_CONTRACT.md)'s `x-forwarded-groups` carries them;
a change bumps `authz_version`, which refreshes or ends sessions according to
each application's `on_authz_change`. Off by default: the header is advisory
for applications, Pumgye never reads it, and receipts never carry groups
([ADR-0018](adr/0018-groups-and-membership-projection.md) decision 6).

## Management API, console and observability

All endpoints are `POST` with a JSON body on the admin listener, under the
console's JSON API rule (`application/json`, `x-hopae-admin-request: 1`,
same-origin `Origin`/`sec-fetch-site`), answered with `cache-control:
no-store`. A Hangang delegated console actor may call each of them with a
signed assertion over the exact body.

### Reads (any granted role)

| Endpoint | Body | Answer |
| --- | --- | --- |
| `/v1/groups/search` | `q` (name substring or key prefix or exact GroupRef, ≤128 chars), `source`, `provider_id`, `include_deleted`, `limit` (1–100, default 50), `cursor` | `items` (group views), `next_cursor` |
| `/v1/groups/get` | `group_id`, `members_limit` (0–200, default 50), `members_cursor`, `privacy_profile` | `group`, `members` (`subject` in the resolve shape, `membership`), `next_members_cursor`, `privacy_profile` |
| `/v1/subjects/groups` | `id` (`u_…` or `human1:…`), `limit` (1–200, default 100), `cursor` | `id`, `user_id`, `status` (`resolved`, `unknown`), `items` (group views with `membership`), `next_cursor` |
| `/v1/subjects/resolve` | as in the [subject directory](SUBJECT_DIRECTORY.md), plus `include_groups` | each person's item gains `groups` (≤20: `group_id`, `name`, `source`) and `groups_truncated` |
| `/v1/subjects/lifecycle` | as in the subject directory, plus `include_groups` | also `group_created`, `group_updated`, `group_deleted`, `member_added`, `member_removed` changes with `group_id` |

Listing cursors are process-bound like every console cursor. Every answered
read writes `admin.read` (`purpose` `groups.read`, `groups.projection`, or
the subject purposes) before the answer.

### Writes (the `admin` role)

| Endpoint | Body | Success |
| --- | --- | --- |
| `/v1/groups/create` | `key` (1–128 of `[A-Za-z0-9._:-]`), `name` (≤256), `description` (≤1024), `reason` | `201 {"group": …}` |
| `/v1/groups/update` | `group_id`, `expected_revision`, `name` and/or `description` (`""` clears), `reason` | `200 {"group": …}` |
| `/v1/groups/delete` | `group_id`, `expected_revision`, `reason` | `200`, the tombstone |
| `/v1/groups/members/add` | `group_id`, `expected_revision`, `user_id`, `expires_at` (optional, within a year), `reason` | `200`, the group |
| `/v1/groups/members/remove` | `group_id`, `expected_revision`, `user_id`, `reason` | `200`, the group |

`reason` is required (1–256 characters) and recorded. Every change to a
group or its members increments its `revision`; a write whose
`expected_revision` differs is `409 revision_conflict` with
`current_revision`. Other answers: `400 invalid_request`, `404
group_not_found`, `404 unknown_user`, `409 key_in_use` (a live local group
has the key), `409 already_member`, `409 not_member`, `409 group_not_local`,
`409 too_many_groups`, `409 group_full` (50,000 members),
`409 too_many_local_groups` (10,000), `410 group_deleted`, `403` from the
console's authentication, role check and actor fence, `429 rate_limited`,
`503 store_unavailable`.

### Audit and limits

Each change writes a required event in the same transaction:
`group.created`, `group.updated` (`attrs.change`: `renamed` or `described`),
`group.deleted` (`attrs.count` members removed), `group.member_added`,
`group.member_removed`, with `attrs.group_id`, `attrs.source`,
`attrs.revision`, `attrs.cause` (`admin`, `login`, `periodic_sync`,
`expired`, `grace_elapsed`, `provider_deleted`, `stale`, `maintenance`), and
for administrator writes the actor attributes and `attrs.note` (the reason).
A refused sync writes the diagnostic `group.sync_refused`. Per-actor token
buckets: group reads 60 burst and 1/s, writes 30 burst and 0.5/s, the
projection 120 burst and 2/s.

## Membership projection for Pumgye

### Requests

`POST /v1/groups/projection/snapshot`:

```json
{"groups": ["grp1:…", "grp1:…"], "limit": 200, "cursor": null}
```

`POST /v1/groups/projection/changes`:

```json
{"groups": ["grp1:…"], "cursor": "r1042", "limit": 200}
```

`groups` is the relevant vocabulary: 1 to 1,024 GroupRefs that the current
Pumgye document references (larger vocabularies are split into shards). The
answer only ever contains memberships of those groups. Without a configured
key both answer `503 projection_unavailable`.

### Envelope and signature

Every answer is one signed envelope:

```json
{"format": "hopae.membership-projection.v1",
 "key": {"issuer_ref": "hopae-groups", "key_epoch": 1},
 "payload": "<base64url without padding: the payload bytes>",
 "signature": "<base64url without padding: Ed25519 signature>"}
```

The signature is Ed25519 over
`"hangang-zerotrust:hopae-membership-projection:v1\0" || payload bytes`.
The payload is a JSON object with the header fields `kind` (`snapshot` or
`changes`), `issuer_ref`, `key_epoch`, `audience`, `store` (the store's
identity), `vocabulary_sha256` (SHA-256 hex of the sorted, de-duplicated
vocabulary joined by `\n`), `issued_at` (milliseconds) and `max_aal` (the
highest AAL Hopae issues, ADR 0021's capability advertisement), and:

- snapshot: `watermark` (the journal revision before the first page),
  `entries` (`principal` — the `human1:` subject, or null when Human
  receipts are not configured — `user_id`, `status`, `groups`),
  `next_cursor` (`p1.<watermark>.<user_id>`), `more`;
- changes: `from`, `head`, `changes` (`revision`, `at`, `change`
  — `group_created`, `group_updated`, `group_deleted`, `member_added`,
  `member_removed` — `group_id`, `user_id`, `principal`), `next_cursor`
  (`r<revision>`), `more`.

### Verification contract (what Pumgye implements)

1. Parse the envelope (unknown fields refused); `format` must be
   `hopae.membership-projection.v1`; the payload at most 4 MiB.
2. Look up the **pinned** public key for `(issuer_ref, key_epoch)` from
   Pumgye's own configuration; never accept a key from the envelope or from
   Hopae. Unknown pair: refuse.
3. Verify the signature strictly (`verify_strict`) over the domain string
   followed by the decoded payload bytes. Only then parse the payload.
4. Require `issuer_ref`/`key_epoch` equal the envelope's, `audience` equal
   Pumgye's own identifier, `vocabulary_sha256` equal the digest of the
   vocabulary Pumgye sent, and `issued_at` within Pumgye's freshness bound
   (and not more than 60 s in the future).
5. Keep `store`: a different value means a different or restored Hopae
   store — discard the projection and take a new snapshot.
6. Apply a snapshot by walking all pages (same vocabulary), then apply the
   feed from `watermark` until `more` is false; the projection revision is
   the last applied `next_cursor`. Changes are set operations, so a replayed
   or overlapping page is harmless. `410 cursor_expired` means the journal no
   longer holds the position (retention, or a foreign store): take a new
   snapshot.
7. Entries with a null `principal` cannot be bound and are ignored.

`hopae::groups::projection::verify` is the reference implementation, and
scenario 312 checks real answers with it.

Key rotation follows the receipt-key rule: configure the next key in Pumgye
first (accept both epochs), then switch Hopae's `groups.projection` to the
new key with `key_epoch + 1`, then retire the old epoch in Pumgye (its floor
rises; older epochs are refused from then on).

## Limitations and compatibility

- Schema 14 is numbered after the passkey branch's 0011–0013, which must
  merge first; a store migrated to 14 without them would not get them later.
- Nested groups, group owners and dynamic (rule-based) groups are out of
  scope.
- Hopae has no subject merge: memberships are never transferred and
  `merged` is not produced.
- Provider memberships of a person are refreshed only at sign-in or by the
  periodic LDAP sync; OIDC groups of a person who no longer signs in stay
  until an administrator disables the person or the provider row is deleted.
- The projection vocabulary is at most 1,024 groups per request.

## Examples, verification and related pages

```sh
curl -sS https://hopae-admin.example.test/v1/groups/create \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -b '__Host-hopae=<redacted>' \
  -d '{"key":"eng.oncall","name":"On-call","reason":"rota 2026-Q4"}'
```

Scenarios [310](../scenarios/310-local-groups.md),
[311](../scenarios/311-provider-group-sync.md),
[312](../scenarios/312-membership-projection.md) and
[313](../scenarios/313-group-lifecycle-feed.md) specify the behavior.
Related: [subject directory](SUBJECT_DIRECTORY.md),
[administration](ADMIN.md), [LDAP authentication](LDAP_AUTHENTICATION.md),
[threat model](THREAT_MODEL.md) (TM-62, TM-63, TM-64).
