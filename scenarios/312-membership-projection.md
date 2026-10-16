# S312 — The signed membership projection: Pumgye's only source of memberships

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0018; Hangang ADR 0021 (membership projection)
- Threat model: TM-63
- Gateway contract: n/a

## Goal

A policy authority obtains, for the groups it names, a paged snapshot and an
incremental feed of memberships whose every page is signed with the
projection key and bound to the audience, the vocabulary and the store, so a
forged, altered, mixed or stale page is refused by the documented verifier.

## Preconditions and fixtures

- `m4-admin` with `groups.projection` (issuer `hopae-groups`, epoch 1, audience `pumgye`, a fixed test seed in the environment).
- Users `u_pa`, `u_pb`, `u_pc`; a relevant group with `u_pa` and `u_pb`, an irrelevant one with `u_pc`.

## Main flow

### S312-1 Snapshot and changes are signed, bounded and resumable

- Given: the fixture.
- When: snapshot of the relevant group with `limit: 1`, its second page; remove `u_pa` from it and add `u_pa` to the other group; read changes from the watermark; verify each page; verify a page of another vocabulary against the first digest; verify a page with a wrong key.
- Then: every page verifies with the reference verifier for its `kind` (`max_aal: 2`); the second page echoes its request cursor and the first page's watermark; the two pages list `u_pa` then `u_pb` with only the relevant group and never `u_pc`; `principal` is null without Human receipts; the feed has exactly one `member_removed` for `u_pa` and `more: false`; the other vocabulary and the wrong key are refused; the reads are recorded with `purpose: groups.projection`.

## Alternative flows

None.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S312-1 | yes: pages bind issue time, store and vocabulary; changes are set operations |
| Tampering | S312-1 | yes |
| Race / timing | — | no: the watermark makes paging and concurrent changes converge |
| Resource exhaustion | S312-A1 | yes |
| Confused deputy | S312-1 | yes: the audience binds the consumer |
| Spoofed or duplicated headers | — | no |
| Downgrade | S312-A2 | yes: without a key there is no unsigned answer |
| Enumeration | S312-1 | yes: only memberships of the named groups are disclosed |

### S312-A1 Pruned or foreign revisions and bad vocabularies are refused

- Given: a key and one group.
- When: an empty, malformed or 1,025-entry vocabulary, a malformed cursor, `limit` 501; a revision beyond the head; a revision older than the oldest kept journal row.
- Then: `400` for each request error; `410 cursor_expired` for both revisions.

### S312-A2 Without a key the projection is unavailable

- Given: no `groups.projection`.
- When: a snapshot request.
- Then: `503 projection_unavailable`; nothing unsigned is returned.

## Observability expectations

- Audit: `admin.read` with `purpose: groups.projection`, `attrs.kind` (`snapshot`, `changes`), `attrs.count`, `attrs.requested` (vocabulary size); empty feed polls are not recorded.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S312-1 | `s312_1_snapshot_and_changes_are_signed_bounded_and_resumable` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S312-A1 | `s312_a1_pruned_or_foreign_revisions_and_bad_vocabularies_are_refused` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S312-A2 | `s312_a2_projection_without_a_key_is_unavailable` | `tests/scenarios/s310_groups.rs` | integration | passing |

The envelope, domain separation, key loading and reuse refusal are also unit
tested in `src/groups/projection.rs`.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run. |

## Open questions

- Should Hopae persist the vocabulary Pumgye publishes, so that a feed can be filtered without the caller resending it?

## 한국어 요약

정책 기관은 이름을 댄 그룹에 대해서만 멤버십 스냅숏과 변경 피드를 받으며, 모든 페이지는
투영 키로 서명되고 대상, 어휘, 저장소에 묶입니다. 위조되거나 바뀌거나 섞이거나 오래된
페이지는 문서화된 검증기가 거부합니다.
