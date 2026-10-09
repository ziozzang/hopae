# ADR-0000: Title in sentence case, stating the decision

- Status: Proposed | Accepted | Superseded by ADR-NNNN (link it) | Deprecated
- Date: YYYY-MM-DD
- Deciders: designer, orchestrator (roles, not names)
- Scenarios: 0NN, 0NN
- Threat model: entries or sections this decision affects, or `n/a`
- Supersedes: ADR-NNNN or `none`

## Context

What forces are at play: the requirement, the constraint from the gateway
contract or the deployment model, the security property that must hold, the
operational cost. State facts with pointers (file, scenario, external spec).
Do not restate the decision here.

## Decision

The decision in one or two sentences, in the active voice: "Hopae stores
sessions server-side and the cookie carries only an opaque identifier."

Then the details that make it unambiguous: interfaces, names, limits, defaults,
and what is explicitly out of scope.

## Consequences

### Positive

- What becomes easier, safer or cheaper.

### Negative

- What becomes harder, what must now be maintained, what guarantee is given up.

### Neutral

- Follow-up work this creates (link roadmap items or scenarios).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Alternative A | The concrete reason it was rejected, with the failure scenario where applicable |
| Alternative B | … |

## Adversarial review

Record each review pass. Findings and context files are internal; this
section is the public summary.

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | YYYY-MM-DD | 0 | 2 | 3 | 1 | 2 × FIX_FIRST applied; 1 × REFUTED (reason below) |

Refuted findings and the evidence that refuted them:

- F-3 claimed X; refuted because Y (pointer to test or reproduction).

Deferred findings and their tracking scenario:

- F-5 → scenario 1NN.

## References

- Specifications, RFCs, related ADRs, design pages.

## 한국어 요약

(Optional.) Two to five sentences in Korean summarizing the decision and its
main consequence. This section does not replace the English record.
