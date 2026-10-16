# S311 — Provider group sync: OIDC claims are mapped, filtered and applied at sign-in

<!-- scenario-status: implemented -->

- Area: providers
- Milestone: M4
- ADRs: 0010, 0019; Hangang ADR 0021
- Threat model: TM-62
- Gateway contract: n/a

## Goal

A provider's group assertion becomes the person's provider groups at sign-in
through the provider's rules, and an assertion that is absent, malformed or
over the limit never changes memberships, while provider groups stay
read-only for administrators.

## Preconditions and fixtures

- `m4-admin` with provider `mock` given `groups: {claim: "groups", include: "^eng-", max_groups: 3, rewrite: "^eng-(.+)$" → "Engineering $1"}`; the mock provider's extra-claims knob sets the ID token's `groups`.
- LDAP: the owned OpenLDAP fixture (`tools/owned_ldap_smoke.py`, `memberof` overlay, image already used by the LDAP qualification) runs `owned_ldap_groups_sync_by_member_of_and_group_search`; DN normalization and subject filters are also unit tested.

## Main flow

### S311-1 The OIDC claim is mapped, filtered and synced at sign-in

- Given: the configuration above.
- When: sign in with `["eng-api","eng-web","sales"]`; an administrator removes the member from a provider group; sign in with `["eng-api"]`; with four `eng-` groups; without the claim; with `["eng-x", 7]`; with `[]`.
- Then: the person has `eng-api` and `eng-web` named `Engineering api`/`Engineering web`, `source: oidc`, provider `mock`; the administrator write is `409 group_not_local`; `eng-web` is removed (grace 0); the over-limit, absent and malformed assertions change nothing; the empty array removes `eng-api`; the two `group.member_removed` events carry `cause: login`.

### S311-2 A provider without a groups section syncs nothing

- Given: provider `mock` without `groups`.
- When: sign in with a `groups` claim.
- Then: no group and no `group.created` event.

## Alternative flows

### S311-3 Stale provider memberships are suspended, then restored

- Given: a person signed in with `["eng-api"]`; default `groups.max_staleness_secs` (7 days).
- When: the clock moves 8 days; the person signs in again with the same claim.
- Then: the maintenance pass sets `stale_at` (the membership stays) and writes `group.membership_stale`; the sign-in clears it and writes `group.membership_restored`.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: an assertion is idempotent |
| Tampering | S311-1 | yes: only the signed, validated ID token or the subject-checked user-info is read |
| Race / timing | — | no: one transaction per assertion |
| Resource exhaustion | S311-1 | yes: per-provider and per-person limits refuse the assertion |
| Confused deputy | S311-1 | yes: administrators cannot edit provider groups |
| Spoofed or duplicated headers | — | no: groups never come from headers |
| Downgrade | — | no |
| Enumeration | — | no |

## Observability expectations

- Audit: `group.created`, `group.updated`, `group.member_added`, `group.member_removed` with `attrs.cause: login` (or `periodic_sync`); diagnostic `group.sync_refused` with the reason.
- Log: `group sync not applied` (warn) with provider and reason.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S311-1 | `s311_1_oidc_claim_is_mapped_filtered_and_synced_at_sign_in` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S311-3 | `s311_3_stale_provider_memberships_are_suspended_then_restored` | `tests/scenarios/s310_groups.rs` | integration | passing |
| S311-2 | `s311_2_provider_without_groups_section_syncs_nothing` | `tests/scenarios/s310_groups.rs` | integration | passing |

Live LDAP case (outside `scenario-coverage`, run by `tools/owned_ldap_smoke.py`):
`provider::ldap::tests::owned_ldap_groups_sync_by_member_of_and_group_search`
— a real OpenLDAP with the `memberof` overlay over LDAPS and StartTLS:
`memberOf` and group search at sign-in yield `cn=eng team,dc=example,dc=test`
named `Eng Team`; the periodic lookup by `entryUUID` finds the same set; an
unknown subject asserts no groups; a wrong password yields no groups.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-16 | 0.0.10 + feat/groups | n/a | owned OpenLDAP (Debian bookworm image, `memberof`) | local Docker | pass | `tools/owned_ldap_smoke.py`, LDAPS and StartTLS |

## Open questions

- Should an absent claim after a previously present one be treated as "no groups" for providers known to always send it?

## 한국어 요약

제공자의 그룹 단언은 로그인할 때 제공자 규칙(포함, 제외, 이름 바꾸기)을 거쳐 그 사람의
제공자 그룹이 됩니다. 클레임이 없거나 형식이 잘못되었거나 한도를 넘으면 멤버십은 바뀌지
않으며, 관리자는 제공자 그룹을 편집할 수 없습니다.
