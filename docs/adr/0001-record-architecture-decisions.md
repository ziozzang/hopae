# ADR-0001: Record architecture decisions as ADRs

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: n/a
- Threat model: n/a
- Supersedes: none

## Context

Hopae is an identity provider that sits in the request path of a zero-trust
gateway. Its decisions about trust boundaries, session models, header contracts
and cryptography must be recoverable later with their reasoning intact,
because every security review and every future change starts by asking why the
current shape exists. The project is built by several roles, some automated,
working in parallel; decisions made in one task brief must be visible to every
other.

The sibling project Hangang kept its early decisions in a single `DECISIONS.md`
page. That works for one decision and degrades as decisions accumulate, are
revised or supersede each other.

## Decision

Every decision that changes an interface, a trust boundary, a data model or a
documented guarantee is recorded as an Architecture Decision Record in
`docs/adr/NNNN-kebab-title.md`, using [the template](0000-template.md).

- Numbers are four digits, allocated sequentially, never reused or renumbered.
- An ADR is `Proposed` while written and reviewed, `Accepted` after its adversarial design review ends with no new S1 or S2 finding, and `Superseded by ADR-NNNN` or `Deprecated` afterwards. Accepted text is not edited except to change status and add links; a changed decision is a new ADR.
- Every ADR carries an "Adversarial review" section summarizing passes, severities and dispositions. Full reports stay internal.
- ADRs are English-only with an optional `## 한국어 요약` section, as recorded in the [documentation system](../DOCUMENTATION.md#exceptions).
- Changes to the [development process](../PROCESS.md) or the documentation system themselves require an ADR.

## Consequences

### Positive

- Reasoning survives personnel and tooling changes; reviews can target a specific recorded claim.
- Supersession is explicit, so "why does the code do this?" has one answer per period of history.
- Parallel implementers read the same accepted record instead of inferring intent from code.

### Negative

- Writing an ADR costs time before implementation starts. The threshold ("interface, trust boundary, data model or guarantee") is meant to keep routine changes out of the process.
- Immutable records can accumulate stale text; readers must follow the status line.

### Neutral

- The documentation index links the ADR directory; no separate ADR index page is maintained while the count is small.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Single `DECISIONS.md` page | No stable identifiers to reference from scenarios and commits; revisions overwrite history; supersession is implicit. |
| Decisions only in commit messages | Not discoverable by topic; cannot carry a review section; lost when history is squashed. |
| Decisions only in design pages | Design pages describe current behavior and are rewritten; the reasoning for rejected alternatives disappears. |
| Full Korean translation of each ADR | Doubles the cost of an immutable record and creates a second text that can drift from the authoritative one; a summary section gives Korean readers the decision without that risk. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Process-establishing record; reviewed by the maintainer at adoption. Later process changes follow the full G2 review. |

## References

- Michael Nygard, "Documenting Architecture Decisions" (2011).
- [Development process](../PROCESS.md), [documentation system](../DOCUMENTATION.md).

## 한국어 요약

인터페이스, 신뢰 경계, 데이터 모델, 문서화된 보장을 바꾸는 모든 결정은
`docs/adr/`에 번호가 붙은 ADR로 기록합니다. 번호는 재사용하지 않고, 수락된
ADR은 상태와 링크 외에는 수정하지 않으며, 결정을 바꿀 때는 새 ADR로 대체합니다.
각 ADR은 적대적 검토 결과 요약을 포함합니다. ADR은 영문으로 작성하고 필요하면
이 절처럼 한국어 요약을 덧붙입니다.
