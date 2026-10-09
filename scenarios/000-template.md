# S000 — Scenario title: actor achieves outcome

<!-- scenario-status: draft -->

- Area: core | sessions | providers | management | lua | webhooks | 2fa | lifecycle | scale-out | security
- Milestone: M1
- ADRs: 0004
- Threat model: TM-xx (threats this scenario exercises)
- Gateway contract: sections touched, or `n/a`

## Goal

One sentence: who gets what, and what must never happen along the way.

## Preconditions and fixtures

- Hopae configuration fragment used by the test (reference a fixture file under `tests/fixtures/`, do not inline secrets).
- Mock provider behavior profile (name from `tests/support/mock_idp`).
- Gateway route fragment when the gateway layer applies.
- Clock, randomness and identifiers that the test injects.

## Main flow

### S000-1 Step name

- Given: initial state in observable terms (stored rows, cookies held, configuration).
- When: one action, with the exact request where it matters (`GET /verify`, headers listed).
- Then: observable outcome — status code, headers emitted, cookie attributes, stored state, log/audit record. Avoid "works correctly".

### S000-2 Step name

- Given:
- When:
- Then:

## Alternative flows

### S000-3 Variant name

- Given:
- When:
- Then:

## Abuse cases

Mandatory. Each category below is either covered by a case or explicitly marked
"does not apply" with a reason. Expected outcomes name the rejection (status,
reason code), the absence of state change, and the audit or log record.

| Category | Case | Applies |
| --- | --- | --- |
| Replay | S000-A1 | yes |
| Tampering | S000-A2 | yes |
| Race / timing | S000-A3 | yes |
| Resource exhaustion | S000-A4 | yes |
| Confused deputy | S000-A5 | yes |
| Spoofed or duplicated headers | S000-A6 | yes |
| Downgrade | — | no: reason |
| Enumeration | S000-A7 | yes |

### S000-A1 Replayed value is rejected

- Given:
- When:
- Then: rejected with …; no session created; audit record `reason=…`; counter `…` incremented.

### S000-A2 …

## Observability expectations

- Log: event name and fields (identifiers only, never credentials).
- Audit: record type and fields.
- Metrics: counter or histogram names and labels.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S000-1 | `s000_1_step_name` | `tests/scenarios/s000_scenario_slug.rs` | integration | planned |
| S000-2 | `s000_2_step_name` | `tests/scenarios/s000_scenario_slug.rs` | integration | planned |
| S000-A1 | `s000_a1_replay_rejected` | `tests/scenarios/s000_scenario_slug.rs` | integration | planned |
| S000-A6 | `s000_a6_spoofed_header_stripped` | `tests/scenarios/s000_scenario_slug.rs` | gateway | planned |

Kinds: `unit`, `integration` (spawned Hopae + mock provider), `gateway`
(adds a live gateway binary), `live` (real provider; G8 only, not in
`cargo test`). Status: `planned`, `failing` (G4 recorded), `passing`.

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| YYYY-MM-DD | 0.1.0 | 0.2.6 | mock / google-test-tenant | staging-a | pass | Environment labels never name internal hosts. |

## Open questions

- Questions that must be answered before the status becomes `approved`.

## 한국어 요약

(Optional.) Two to five sentences describing the scenario and its key abuse
case in Korean.
