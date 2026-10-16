# S310 — Local groups: administrators manage groups and members with compare-and-swap and audit

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0016, 0018; Hangang ADR 0021 (groups owned by Hopae)
- Threat model: TM-62, TM-64
- Gateway contract: n/a

## Goal

An administrator creates, renames, describes and deletes local groups and
adds and removes members, each with a reason and the group's expected
revision, so concurrent edits never overwrite each other silently, every
change is recorded with its actor and reason in the transaction that made it,
and a read-only administrator can read but never write.

## Preconditions and fixtures

- Configuration `tests/fixtures/m4-admin.json` with the overrides of `dkit::overrides` (scenario 307).
- A user `u_g1` laid down with SQL; administrators signed in through the real flow and granted with the store (`kit` of scenario 301).

## Main flow

### S310-1 A local group's lifecycle with compare-and-swap and audit

- Given: an administrator and `u_g1`.
- When: create `eng.backend`; create it again; update with `expected_revision: 7`; update name and description at revision 1; add `u_g1`; add it again; add `u_nobody`; read the detail, `u_g1`'s groups, a resolution with and without `include_groups`, a search; remove the member; delete the group; update the tombstone; create `eng.backend` again.
- Then: `201` with a `grp1:` reference, `source: local`, revision 1; `409 key_in_use`; `409 revision_conflict` with `current_revision: 1`; revision 2 then 3 with one member; `409 already_member`; `404 unknown_user`; the detail lists `u_g1` with a masked address, the reason and the acting administrator; the resolution carries `groups` and `groups_truncated` only when asked; removal and deletion succeed (`state: deleted`); the tombstone answers `410 group_deleted` and still resolves; the key is free again under a new reference; `group.created` (2), `group.updated` (1), `group.member_added`, `group.member_removed` and `group.deleted` events carry the group, source, actor and reason.

### S310-2 Viewers read groups but cannot write

- Given: an administrator and a viewer.
- When: the viewer creates a group and reads one.
- Then: `403 role_insufficient` for the write; `200` for the read, recorded as `admin.read` with `purpose: groups.read`.

## Alternative flows

### S310-3 Deleting a group with members requires force

- Given: a local group with one member.
- When: delete with `force: false`, without `force`, then with `force: true`.
- Then: `409 group_not_empty` twice; then `200`, the tombstone has no member and `group.deleted` carries `attrs.count: 1`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: a replayed write meets the advanced revision (`409`); delegated replays are refused by the nonce admission (307-5) |
| Tampering | S310-1, S310-A1 | yes |
| Race / timing | S310-1 | yes: compare-and-swap on the group revision |
| Resource exhaustion | S310-A1, S310-A2 | yes |
| Confused deputy | S310-2 | yes |
| Spoofed or duplicated headers | — | no: the JSON API rule of 307-A2 applies unchanged |
| Downgrade | — | no |
| Enumeration | — | no: any grant may list groups, which is the purpose |

### S310-A1 Malformed bodies and bounds are refused before any write

- Given: an administrator and one group.
- When: a key with a space, an empty name, a missing reason, a body naming another operation, a 257-character reason, an update changing nothing, a malformed reference, a non-user ID, an `expires_at` in the past, `limit` 101, an unknown source, `members_limit` 201, `limit` 0 for a person's groups, a forged cursor.
- Then: `400` for each; no group or membership event beyond the fixture.

### S310-A2 Writes are rate-limited per actor

- Given: an administrator.
- When: 31 group writes in a burst.
- Then: the 31st is `429 rate_limited` with `retry-after`.

## Observability expectations

- Audit: required `group.*` events with `attrs.group_id`, `attrs.source`, `attrs.revision`, `attrs.cause: admin`, `attrs.note` and the actor attributes; `admin.read` for reads.
- Metrics: `hopae_admin_mutations_total{kind}`, `hopae_events_total{kind="group.*"}`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S310-1 | `s310_1_local_group_lifecycle_with_cas_and_audit` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S310-2 | `s310_2_viewers_read_but_cannot_write` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S310-3 | `s310_3_deleting_a_group_with_members_requires_force` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S310-A1 | `s310_a1_bodies_and_bounds_are_refused_before_any_write` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S310-A2 | `s310_a2_per_actor_write_rate_limit` | `tests/scenarios/s310_groups.rs` | integration | passing |

Store-level semantics (journal rows, the gateway mirror, maintenance expiry)
are covered by the unit tests in `src/store/sqlite/groups.rs`.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- None. (Deleting a group with members requires `force: true`, case 310-3.)

## 한국어 요약

관리자는 사유와 기대 리비전을 붙여 로컬 그룹을 만들고, 이름과 설명을 바꾸고, 삭제하며
구성원을 더하고 뺍니다. 비교 후 교체로 동시 편집이 조용히 덮어쓰이지 않고, 모든 변경은
행위자와 사유를 담은 필수 이벤트로 같은 트랜잭션에 기록됩니다. 읽기 전용 관리자는 읽을
수만 있습니다.
