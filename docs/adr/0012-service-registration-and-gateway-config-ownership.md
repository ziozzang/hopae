# ADR-0012: The gateway owns routes, Hopae owns authentication policy; gateway configuration is proposed before it is written

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator, maintainer
- Scenarios: 008 (M1 manual registration); later milestones add 3xx/6xx scenarios per phase
- Threat model: TM-15, TM-19
- Supersedes: none

## Context

- Open question from the maintainer: should Hopae dynamically add and remove protected services and manage the gateway's configuration through its admin API or a shared store? Who is the source of truth for routes versus authentication policy, and how are dual-writer conflicts avoided?
- Agreed risk 3: configuration synchronization is a scope-creep magnet; the maintainer agreed to a phased approach (manual → generated proposal → automatic).
- Gateway facts (2026-10-09): routes are whole JSON objects with `deny_unknown_fields`; `POST /v1/routes/http` creates a route under revision compare-and-swap; `GET /v1/routes/http[/<id>]` reads; whole-configuration writes go through an acceptance journal with administrator authority; configuration changes in the reference deployment are made only through the admin API. There is no field-level patch and no "managed by" marker on routes.
- Protecting a service needs both sides: a route with `auth` on the gateway and an application row with policy in Hopae. Only the pair is a working configuration.

## Decision

**Ownership.** Exactly one writer per field, forever:

| Field group | Owner | Other side |
| --- | --- | --- |
| Routes: hosts, paths, priority, backends, listeners, TLS, caching, transforms, Lua | Gateway (operator via its admin API or console) | Hopae reads them (phase 1+) and never writes them |
| Authentication policy: applications, hosts → policy, binding, lifetimes, step-up, blocks, providers, users, sessions | Hopae | The gateway never reads them; it only calls verify |
| The `auth` block of a route (URL, listed headers, timeout, `forward_response`, decision cache, static headers) | Phase 0–1: operator. Phase 2: Hopae for routes the operator has marked as Hopae-managed, and nothing else | Rendered by Hopae from the contract; identical in every phase |

**Phases.**

| Phase | Milestone | Behavior | Evidence of safety |
| --- | --- | --- | --- |
| 0 — Manual | M1 | The operator creates the route with the `auth` fragment from the contract page and the application row in Hopae. `hopae --check` warns when an application host has no corresponding route it can see (if a gateway read-only credential is configured) | No writes by Hopae |
| 1 — Proposal and drift | M2/M4 | `hopae gateway render --app <id>` prints the route `auth` fragment (and a full route skeleton on request). With a read-only gateway credential, Hopae compares its applications to the gateway's routes and reports drift (missing route, missing identity header in `response_headers`, `forward_response` false, timeout out of range, **a registered host whose DNS does not resolve to the gateway's public addresses**, which would be an open credential destination) in the console and in `hopae --check`. Nothing is written | Read-only credential; diff only |
| 2 — Apply with consent | M7 or later, by a new ADR, **and only after gateway change HC-7 exists** | For routes whose id is listed in `gateway.managed_routes` by the operator, Hopae may apply the rendered `auth` block through a gateway endpoint that accepts **only** the `auth` sub-resource of a route (`PUT /v1/routes/http/<id>/auth`, HC-7) with a credential whose scope the gateway enforces as "auth block of these route ids", under the gateway's revision CAS, after showing the diff and receiving an explicit console confirmation per change. The whole-route `PUT` is never used by Hopae. Conflicts abort and are shown | Gateway-enforced field scope and id scope (HC-7); CAS; human confirmation; audit on both sides. Client-side diffing is a courtesy, not the boundary (review finding R13) |

A phase advances only when the previous one has run in the reference
deployment for one minor version without an incident report, and only by a
new ADR that supersedes the relevant row here. Without HC-7, phase 2 does not
exist: a route-id allowlist on the whole-route `PUT` would let a defective or
compromised Hopae change backends, hosts, priority or `access_mode`.

**Non-goals, permanently:** a shared configuration store between the two
products; Hopae creating or deleting routes; Hopae holding a gateway
administrator credential with more than route-read (phase 1) or
route-write-for-allowlisted-ids (phase 2) scope; gateway reading Hopae's
database.

## Consequences

### Positive

- No dual writer exists at any phase; the field-level ownership table is the invariant reviewers check.
- Operators get value early (rendered fragments, drift report) without granting write access.
- The pairing problem (route without application, application without route) is detected instead of discovered by users.

### Negative

- Phase 0 is two manual steps per service; the drift report in phase 1 is the remedy, not automation.
- Phase 2 depends on a gateway capability that does not exist yet (HC-7: an `auth`-only route sub-resource with a credential scoped to it and to listed route ids); it is a gateway task to define before phase 2 can start.

### Neutral

- The reference deployment's rule "configuration changes via the admin API only" is preserved in every phase.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Hopae as the source of truth for routes (full management of the gateway) | Reproduces the gateway console inside Hopae; conflicts with operator edits; a Hopae bug could unroute production traffic. |
| Shared configuration store (both read and write one document) | Two products with different schemas and release cycles writing one document is the dual-writer problem itself; the gateway's CAS protects revisions, not semantics. |
| Hopae writes immediately on application creation (no proposal phase) | Skips the evidence that rendering is correct; the phased plan reaches the same end state with a record. |
| Gateway pulls policy from Hopae (gateway as the client) | Inverts the dependency: the gateway would need Hopae at configuration time, and a Hopae outage would block unrelated gateway changes. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-10-09 | 0 | 1 | 0 | 0 | 1 × FIX_FIRST applied (R13) |
| 2 | 2026-10-09 | 0 | 0 | 0 | 0 | R13 CLOSED; the phase-1 drift check gains the dangling-host rule from N03 |
| 3 | 2026-10-09 | 0 | 0 | 0 | 0 | N03 CLOSED (a registered host later allowed to dangle is an accepted operator risk; DNS drift reporting starts in phase 1). Accepted pending confirmation pass. |
| 4 | 2026-10-09 | 0 | 0 | 0 | 0 | No finding in pass 4. Accepted pending confirmation pass. |

Findings and dispositions:

- R13 (S2): a route-id allowlist plus CAS on the whole-route `PUT` does not restrict which fields change. FIX_FIRST: phase 2 requires HC-7 (gateway-enforced `auth`-only sub-resource and credential scope); without it phase 2 does not exist.

Reviewer confirmation recorded: phases 0 and 1 (render and read-only drift)
avoid writes and stand. Open for the reviewer: is the read-only gateway
credential of phase 1 itself an unacceptable widening of Hopae's blast
radius?

## References

- Gateway `src/admin.rs` (`/v1/routes/http`, revision CAS), `docs/CONFIG_OPERATIONS.md` (acceptance journal), reviewed 2026-10-09.

## 한국어 요약

라우트(호스트, 경로, 백엔드 등)는 게이트웨이가, 인증 정책(애플리케이션,
바인딩, 세션, 제공자, 사용자)은 Hopae가 소유하며 필드마다 작성자는 하나뿐입니다.
0단계(M1)는 운영자가 수동으로 양쪽을 등록하고, 1단계는 Hopae가 라우트 `auth`
조각을 생성해 보여 주고 읽기 전용으로 불일치를 보고하며, 2단계는 별도 ADR로
운영자가 허용한 라우트의 `auth` 블록만 CAS와 확인을 거쳐 적용합니다. 공유
설정 저장소와 라우트 생성·삭제는 영구적으로 하지 않습니다.
