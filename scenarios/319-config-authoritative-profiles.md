# S319 — Configuration-authoritative profiles: a declarative package changes authentication profiles by changing the file

<!-- scenario-status: implemented -->

- Area: management
- Milestone: M4
- ADRs: 0016; Hangang ADR 0022 (Kubernetes-native package)
- Threat model: TM-45
- Gateway contract: n/a

## Goal

With `authentication.source = config`, every start reconciles the stored
authentication profiles and projection plan to the configuration file through
the validated CAS publication, so a Helm upgrade never needs a database reset;
an invalid file never touches the store, console edits are refused, and the
default `store` mode keeps today's behavior.

## Preconditions and fixtures

- Unit: an in-memory `meta` table and the authority's reconciliation entry point.
- Integration: `m4-admin` with the subject-directory API profile (`api`,
  networks `192.0.2.0/24`) and `authentication.source = config`; an
  administrator.

## Main flow

### S319-1 Reconciliation through the publication

- Given: an empty store.
- When: a start with profile A, again with A, then with B; a start whose profiles fail validation or reference an absent credential; then a start with no profiles.
- Then: revision 1 (changed), 1 (unchanged), 2 (changed); the invalid starts are refused and the store keeps revision 2 with B; no profiles publishes the disabled tombstone at 3; every change has an audit row with actor `config`.

### S319-2 Config mode on the real binary

- Given: the instance in config mode.
- When: the profiles are read and a console edit is attempted; the file's networks change and the instance restarts; it restarts unchanged; it switches back to store mode with another file change and restarts.
- Then: revision 1 with `source: config`; the edit is `409 config_authoritative` and nothing changes; after the change revision 2 carries the new networks and `authentication.reconciled` records `profiles`, 1 → 2, actor `config`; the unchanged restart keeps revision 2 with no new event; in store mode revision 2 stays and the file change is ignored.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no: no request credential is involved |
| Tampering | S319-1 | yes: an invalid file is refused before any store write |
| Race / timing | S319-1 | yes: the CAS revision of the publication applies to reconciliation |
| Resource exhaustion | — | no: the document bounds of the publication apply unchanged |
| Confused deputy | S319-2 | yes: a console edit cannot silently diverge from the declared file |
| Spoofed or duplicated headers | — | no: the console's existing rules apply |
| Downgrade | S319-2 | yes: switching back to store mode keeps the last reconciled document |
| Enumeration | — | no |

## Observability expectations

- Log: `authentication profiles reconciled to the configuration` with previous and new revision.
- Audit: publication audit row (actor `config`); required event `authentication.reconciled`.
- Metrics: none new.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S319-1 | `s319_1_config_authoritative_start_reconciles_through_publication` | `src/auth_gateway/authority.rs` | unit | passing |
| S319-2 | `s319_2_config_mode_reconciles_on_start_and_refuses_console_edits` | `tests/scenarios/s319_config_authoritative_profiles.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | not run | Helm qualification re-run is the next step. |

## Open questions

- Whether the Helm chart should default to `config` mode.

## 한국어 요약

`authentication.source = config`이면 시작할 때마다 검증된 CAS 게시로 저장된 인증 프로필과 투영 계획을 설정 파일에 맞추므로 Helm 업그레이드에 DB 초기화가 필요 없습니다. 잘못된 파일은 저장소를 건드리지 않고, 콘솔 편집은 거부되며, 기본 `store` 모드는 기존 동작을 유지합니다.
