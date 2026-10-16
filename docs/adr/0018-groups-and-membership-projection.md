# ADR-0018: Hopae owns groups and publishes memberships to Pumgye as a signed, vocabulary-bound projection

- Status: Proposed
- Date: 2026-10-16
- Deciders: designer, orchestrator
- Scenarios: 310, 311, 312, 313
- Threat model: TM-62, TM-63, TM-64
- Supersedes: none (fills the *later* `groups` column of `users` in the [architecture](../ARCHITECTURE.md#data-model); extends the subject directory of [SUBJECT_DIRECTORY.md](../SUBJECT_DIRECTORY.md))

## Context

- Hangang ADR 0021 (Pumgye authorization model revision) moves Pumgye to a
  principal / group / role-template / binding model and assigns **groups and
  memberships** — local, LDAP `memberOf`, OIDC `groups` claim — to Hopae.
  Pumgye holds only GroupRefs (`grp1:<26 crockford>`) in bindings and learns
  memberships from a "revisioned, signed export of principal → [GroupRef]
  restricted to groups referenced by the current Pumgye document". Pumgye
  must never read LDAP or OIDC directly nor trust group names from request
  headers. The same ADR asks Hopae for group lifecycle and membership changes
  in its lifecycle feed and for a capability advertisement (highest AAL) in
  the projection header.
- Hopae had no groups: `users.groups` was an always-empty JSON column, the
  gateway contract's `x-forwarded-groups` was therefore never sent, and the
  LDAP and OIDC providers returned no group data.
- The subject directory (scenarios 307, 308) already offers resolution, a
  durable outbox-based lifecycle feed with cursors and `410 cursor_expired`,
  audited reads and per-actor buckets; the console has a fenced mutation path
  with required `admin.*` events in the same transaction.
- Hopae already signs receipts with Ed25519 keys referenced from the
  environment (`receipt_issuer`: public key in the file, seed by variable
  name, key epoch) and keeps signature purposes separate.
- Commercial identity providers (Okta, Keycloak) treat directory-synced
  groups as read-only in the console, refresh them at sign-in and on a
  schedule, map claims by rules, and give every write an audit record.

## Decision

Hopae owns groups and memberships, writes each group from exactly one source,
and publishes memberships to Pumgye only through a signed projection bound to
the vocabulary Pumgye asks for.

1. **Model.** `directory_groups` (GroupRef, `source` local/ldap/oidc,
   provider, stable source key, name, description, state, CAS `revision`,
   timestamps, `last_seen_at`), `group_members` (person = Hopae user ID,
   source, provider, first/last seen, local `expires_at`, provider
   `removal_pending_at`, local `added_by`/`reason`), `group_changes` (the
   projection journal, `AUTOINCREMENT` revision) and `group_sync_state`.
   A GroupRef is 128 random bits, never reused; deletion leaves a tombstone.
   Nested groups are out of scope.
2. **Single writer per group.** Provider groups are written only by their
   provider's sync (administrator writes answer `409 group_not_local`); local
   groups only by administrators. Every write appends journal rows and
   required `group.*` events in the same transaction.
3. **Sync semantics.** A provider assertion is the person's complete set from
   that provider. Rules (include, exclude, rewrite) are linear-time regular
   expressions; an assertion that exceeds the provider's `max_groups`, the raw
   bound (4,096) or `groups.max_groups_per_user` is refused whole, never
   truncated. An absent or malformed claim is "not asserted"; an empty array
   asserts no groups. Unasserted memberships are removed immediately or after
   `removal_grace_secs`. Sync happens at sign-in (OIDC claim from the ID token,
   else user-info; LDAP `memberOf` or group search with the service bind,
   applied only after the password is verified) and, for LDAP, in a bounded
   periodic refresh of linked identities. A sync never blocks a sign-in; a
   failed sync keeps the previous memberships (fail-static, documented as a
   residual).
4. **Administration.** POST JSON endpoints on the admin listener for search,
   detail with members, a person's groups, `include_groups` on resolution,
   and local writes with a required reason and `expected_revision`
   (compare-and-swap on the group revision). Reads are `admin.read`-audited
   and bucketed like the subject directory; writes are console mutations
   (CSRF, `admin` role, actor fence) with their own bucket.
5. **Projection.** Snapshot pages (people with their memberships among the
   vocabulary, with a watermark) and a journal feed (`r<revision>` cursors,
   `410` after retention or for a foreign store), restricted to a
   caller-supplied vocabulary of at most 1,024 GroupRefs. Each page is an
   envelope whose payload bytes are signed with Ed25519 under the domain
   `hangang-zerotrust:hopae-membership-projection:v1\0`. The payload binds
   issuer, key epoch, audience, the store identity, the vocabulary digest,
   the issue time and `max_aal`. The key is a dedicated `groups.projection`
   key loaded like the receipt issuer's and refused if it equals the receipt
   key. Pumgye pins keys by `(issuer_ref, key_epoch)`; rotation is
   add-next-then-switch-then-retire.
6. **Gateways and receipts.** Groups are **not** emitted to gateways by
   default. `groups.gateway_header: true` mirrors at most 32 GroupRefs into
   `users.groups` (bumping `authz_version`) so the existing
   `x-forwarded-groups` header carries them for applications; GroupRefs, not
   names, because names are mutable and can collide across sources. Receipts
   never carry groups: Pumgye's decisions use the signed projection only.
7. **Lifecycle feed.** `subjects/lifecycle` reports group lifecycle and
   membership changes only with `include_groups: true`, so the PR #4 contract
   is unchanged by default.
8. **Migration.** The schema is migration `0014_groups`; 0011–0013 belong to
   the passkey branch, which must merge first because the runner applies only
   versions above the recorded maximum.

## Consequences

### Positive

- One owner for groups across the stack; Pumgye gets an authenticated,
  minimal (vocabulary-restricted) and replay-harmless membership source.
- Directory-synced data cannot be edited by hand, and every change, whoever
  made it, is audited in the transaction that made it.
- Over-limit or partial provider answers can only fail static, never silently
  shrink a person's groups.

### Negative

- Memberships of people who never sign in again are refreshed only for LDAP
  (periodic sync); OIDC memberships stay until sign-in, disablement or
  provider deletion.
- While a directory is unreachable, memberships it would remove stay
  effective.
- Large deployments must shard the vocabulary (1,024 per request).
- The migration number depends on another branch's merge order.

### Neutral

- Follow-up: console pages for groups; SCIM provisioning; Pumgye's consumer
  (out of this repository).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Pumgye reads LDAP/OIDC groups itself | Rejected by Hangang ADR 0021: a second directory with its own connectors and trust in tokens |
| Ship groups in receipts or in `x-forwarded-groups` to Pumgye | Headers are spoofable by anything between the gateway and Pumgye and are unbounded per request; ADR 0021 forbids trusting them |
| Sign canonical JSON | Canonicalization is a classic verification bug source; signing the exact payload bytes avoids it |
| Reuse the receipt signing key | Mixes purposes; a receipt verifier could be confused about what a signature means. A separate key and domain keep the purposes apart |
| Truncate an oversized assertion to the limit | Removes memberships the provider still asserts, at random; refusing keeps the last good state and is visible |
| Nested groups | Needs cycle and depth bounds and expands evaluation cost; no consumer requires it yet |
| Group names as stable identifiers | Names change and collide across sources; GroupRefs do neither |

## Adversarial review

Not yet reviewed (G2 pending). The PR records the open questions.

## References

- Hangang ADR 0021 (Pumgye authorization model revision): groups,
  membership projection, lifecycle feed, AAL capability.
- [ADR-0009](0009-event-model.md) event model, [ADR-0016](0016-management-console-minimum.md) console.
- [Groups and the membership projection](../GROUPS.md), [subject directory](../SUBJECT_DIRECTORY.md).
- RFC 8032 (Ed25519), OpenID Connect Core 1.0 §5.3.2.

## 한국어 요약

Hopae가 그룹(로컬, LDAP, OIDC)과 멤버십을 소유하며, 그룹마다 쓰는 주체는 하나뿐입니다
(제공자 그룹은 그 제공자의 동기화만, 로컬 그룹은 관리자만). 제공자 단언은 전체 집합으로
적용하고, 한도를 넘으면 잘라 내지 않고 통째로 거부합니다. Pumgye에는 요청한 어휘로
제한되고 전용 Ed25519 키로 서명된 스냅숏과 변경 피드로만 멤버십을 알립니다. 게이트웨이
헤더로의 그룹 전달은 기본값이 꺼짐이며, 영수증에는 그룹이 실리지 않습니다.
