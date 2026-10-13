# Development process

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/PROCESS.md)

This document defines how every change to Hopae is designed, reviewed, tested,
released and deployed. It is binding for humans and for automated agents. The
process is defined by **responsibilities and evidence**, not by who or what
produces them: a change is accepted because the required artifacts exist and the
required checks ran, never because of the author's role.

The governing rule is **gate ≠ done**. Passing a gate is necessary to continue;
it is not evidence that the change is finished or correct. "Done" is defined in
the [definition of done](#definition-of-done).

## Roles

| Role | Owns | Does not do | Involved when |
| --- | --- | --- | --- |
| Designer | Architecture and design decisions; design documents and [ADRs](adr/); responses to design-review findings; approval of security-critical scenarios. | Routine implementation, file-level edits, triage of ordinary bugs. | A decision changes an interface, a trust boundary, a data model, or a documented guarantee, or when two implementers disagree. Not consulted for work that an existing ADR already settles. |
| Orchestrator | Work breakdown, task briefs with explicit file ownership, integration, gate verification, review-context files, disposition of review findings, commits. | Silent scope changes; accepting an implementer's report without checking its evidence. | Every change, start to finish. |
| Implementer | One task brief at a time; the files listed in that brief; failing tests first, then the implementation; an evidence-bearing report. | Editing files outside the brief's ownership list (ask the orchestrator instead); weakening or deleting tests to make them pass; deciding architecture. | Implementation and test phases. Several implementers run in parallel only with disjoint file ownership. |
| Adversarial reviewer | Independent refutation of designs, analyses and code from a supplied context file. Severity-ordered findings, each with a concrete failure scenario and a pointer. | Fixing code; approving; softening findings to be agreeable. | Design review (G2) and code review (G7); also any analysis another phase will build on. |
| Maintainer (human) | Final authority on scope, releases and deployment; custody of secrets and the release signing seed. | Delegating custody of secrets to any agent or file in the repository. | Release, deployment, and any decision the roles above escalate. |

Which tools or models fill each role, and the exact commands used to invoke
them, are recorded in `internal/PROCESS_ROLES.md`, which is not published.
Public documents name roles only, because the responsibilities are stable while
the tools change, and because tooling details belong to the operating
environment rather than to the product.

## Phase gates

Each change moves through the gates below in order. A gate's exit checklist
must be satisfied before the next gate starts. Skipping a gate requires a
written reason in the task record and the maintainer's agreement; security-
relevant changes cannot skip G2, G7 or G8.

| Gate | Name | Primary artifact |
| --- | --- | --- |
| G1 | Design document and ADR | `docs/<TOPIC>.md` draft and `docs/adr/NNNN-*.md` (Proposed) |
| G2 | Adversarial design review | Review report (internal) and ADR findings section |
| G3 | Scenario specifications | `scenarios/NNN-*.md` (Approved) |
| G4 | Failing tests | Test functions named after scenario cases; recorded failing run |
| G5 | Implementation | Code within the owned files; tests passing |
| G6 | Automated checks | `make check`, `cargo test`, `cargo audit`, `make check-docs`, `make scenario-coverage` all green |
| G7 | Adversarial code review | Review report (internal); dispositions applied |
| G8 | Live end-to-end | Scenario run against a spawned Hopae plus a live gateway and, where possible, real providers; `verified-live` status |
| G9 | Deploy | Reference deployment updated; smoke login passed; rollback path confirmed |

### G1 Design document and ADR

Entry: a roadmap item or a defect that changes behavior.

Exit checklist:

- [ ] Design document states the goal, non-goals, interfaces, data touched, failure behavior and operator-visible effects.
- [ ] Every decision that changes an interface, trust boundary, data model or guarantee has an ADR in `Proposed` status using [the template](adr/0000-template.md).
- [ ] The threat model (`docs/THREAT_MODEL.md`) has a drafted delta for any security-relevant change: new assets, entry points, trust boundaries, and the mitigations relied on.
- [ ] Open questions are listed explicitly; none is hidden inside prose.

### G2 Adversarial design review

Entry: G1 artifacts exist.

Exit checklist:

- [ ] A review context file was supplied following the [review protocol](#adversarial-review-protocol).
- [ ] Every S1 and S2 finding has a disposition of `FIX_FIRST` applied, or `REFUTED` with evidence recorded.
- [ ] The ADR's "Adversarial review" section lists findings by severity and the dispositions.
- [ ] The ADR moves to `Accepted` only after the final pass yields no new S1 or S2 finding.

### G3 Scenario specifications

Entry: ADR accepted.

Exit checklist:

- [ ] Each user-visible or security-visible behavior has a scenario in `scenarios/` using [the template](../scenarios/000-template.md).
- [ ] Every scenario includes abuse cases, not only the happy path.
- [ ] Every case has a planned test name and kind (unit, integration, live).
- [ ] Scenario status is `approved`; security-critical scenarios were approved by the designer.

### G4 Failing tests

Entry: approved scenarios.

Exit checklist:

- [ ] A test exists for each scenario case, named per the [naming rule](#mapping-scenarios-to-tests).
- [ ] Each test was run and **failed for the intended reason** (an assertion, not a compile error or missing fixture); the failing output is attached to the task record.
- [ ] Tests do not depend on wall-clock sleeps, network access outside loopback, or shared mutable fixtures.

### G5 Implementation

Entry: failing tests recorded.

Exit checklist:

- [ ] Only files in the task brief's ownership list changed; any exception was approved by the orchestrator and recorded.
- [ ] All tests from G4 pass without modification of their assertions. A test may be changed only with an explanation in the commit body.
- [ ] No `unwrap()`/`expect()` on untrusted input paths; errors are typed and logged without secrets.
- [ ] New configuration keys are documented in the configuration reference in the same change.

### G6 Automated checks

Entry: implementation complete.

Exit checklist (all must be run from a clean working tree and all must pass):

- [ ] `make check` — `cargo fmt --all -- --check` and `cargo clippy --all-targets --locked -- -D warnings`.
- [ ] `cargo test --locked --all-targets`.
- [ ] `cargo audit` with no unaddressed advisory; an accepted advisory is listed in `.cargo/audit.toml` with a reason and an expiry date.
- [ ] `make check-docs` — links, navigation, heading structure, language placement, translation status, publication policy.
- [ ] `make scenario-coverage` — every approved scenario case maps to an existing test and every scenario-named test maps to a scenario.

### G7 Adversarial code review

Entry: G6 green.

Exit checklist:

- [ ] Review context file supplied with claims, pointers and prior reports.
- [ ] Reviewer default stance was refutation; findings are severity-ordered with failure scenarios.
- [ ] S1/S2 findings fixed and re-verified; S3 fixed or tracked with a scenario; S4 at the orchestrator's discretion.
- [ ] Repeated until a pass produces no new S1/S2 finding. Each pass gets the previous report path.

### G8 Live end-to-end

Entry: G7 complete.

Exit checklist:

- [ ] The scenario's main flow and at least its highest-severity abuse case ran against a spawned Hopae binary **and** a live gateway instance, not only the mock.
- [ ] Where a real provider is involved and a test tenant exists, the main flow ran against the real provider; otherwise the mock run is recorded as the ceiling of evidence and the scenario stays `implemented`, not `verified-live`.
- [ ] The run record (date, versions, environment label, result) is attached to the scenario's live-verification section. Environment labels never name internal hosts.
- [ ] Any difference between mock and live behavior was fed back into the mock provider and the scenario.

### G9 Deploy

Entry: G8 complete and a release or pre-release is tagged.

Exit checklist:

- [ ] Configuration preflight passed against the deployment's real configuration (`hopae --check`).
- [ ] State was backed up before the change; the previous image or binary remains available for rollback.
- [ ] Deployment replaced; smoke login through the gateway succeeded; logout succeeded.
- [ ] Rollback was rehearsed at least once per minor version.
- [ ] A deployment receipt was written to the internal deployment record, not to the repository.

## Adversarial review protocol

The reviewer's job is to **refute**. The default assumption is that every claim
is wrong, that every check is theater until proven otherwise, and that any gate
that cannot observe its input is worse than no gate. This applies to designs
and analyses as much as to code: a capability survey, a "this is already
handled" conclusion or a threat-model delta is reviewed the same way before
anything is built on it.

### Context file

The orchestrator writes one context file per review pass. It contains:

1. **Scope** — what is under review and what is explicitly out of scope.
2. **Claims** — numbered, falsifiable statements the change relies on ("C3: a replayed `state` value is rejected before any token exchange").
3. **Pointers** — file paths with line ranges, scenario IDs, ADR IDs, threat-model entries for each claim.
4. **Prior reports** — paths to earlier review reports for this change and the disposition of each earlier finding.
5. **Questions** — specific places the orchestrator is least sure about.
6. **Rules** — severity scale, output format, and "do not fix, only refute".

### Severity scale

| Severity | Meaning | Required disposition |
| --- | --- | --- |
| S1 | Security boundary bypass, data loss, or a guarantee the documentation makes that does not hold | `FIX_FIRST` before any merge, or `REFUTED` with reproduced evidence |
| S2 | Correctness defect reachable by a user or operator in a documented flow | `FIX_FIRST` before merge |
| S3 | Defect reachable only under unusual configuration, or a missing abuse case | `FIX` in the change or `DEFERRED` with a scenario and roadmap entry |
| S4 | Style, naming, clarity | Orchestrator's discretion |

### Output and disposition

Each finding states: ID, severity, the claim it refutes, a concrete failure
scenario (inputs, sequence, observed vs expected), a pointer, and a suggested
fix. The orchestrator records a disposition per finding: `FIX_FIRST`, `FIX`,
`REFUTED` (with evidence, never with assertion), or `DEFERRED` (with the
tracking scenario). Review reports and context files live under
`internal/reviews/` and are not published; the public record is the ADR's
review section, the CHANGELOG `Security` entries, and the threat model.

## Scenario-based TDD

Scenarios are the executable contract between the design and the tests. A
behavior that has no scenario is not specified; a scenario that has no test is
not implemented.

### Scenario files

- One file per scenario: `scenarios/NNN-kebab-name.md`, from [the template](../scenarios/000-template.md).
- `NNN` ranges are allocated by area (see [`scenarios/README.md`](../scenarios/README.md)); the roadmap refers to these ranges.
- Each scenario has: goal, preconditions, main flow in Given/When/Then, alternative flows, **mandatory abuse cases**, observability expectations, a test-mapping table and a live-verification record.
- Status lifecycle: `draft` → `approved` → `implemented` → `verified-live`. Only the orchestrator or designer changes status, and only with the gate evidence.
- Abuse cases must at least consider: replay, tampering, race/timing, resource exhaustion, confused deputy, spoofed or duplicated headers, protocol downgrade, and enumeration. A scenario may state that a category does not apply, with a reason.

### Mapping scenarios to tests

- Test function names start with the scenario case ID in lower case: scenario `012`, case `012-3` → `fn s012_3_<slug>()`; abuse case `012-A2` → `fn s012_a2_<slug>()`.
- Integration tests live in `tests/scenarios/`, one file per scenario (`s012_<slug>.rs`) or per area when scenarios are small. Unit tests may carry scenario names too, but every scenario case needs at least one integration-level test unless the scenario marks it `unit-only` with a reason.
- The scenario's test-mapping table lists every test name and file. `make scenario-coverage` checks both directions: each listed test exists, and each `sNNN_` test is listed in a scenario. Unmapped items fail the build once the scenario is `approved`.

### Test harness

| Layer | What runs | Used by |
| --- | --- | --- |
| Unit | Pure functions and state machines with injected clock and randomness | Any case marked `unit` |
| Integration | A spawned Hopae binary on loopback with a temporary state directory, plus the in-repo mock OAuth/OIDC provider | Every scenario case by default |
| Gateway | Integration layer plus a live gateway binary when `HOPAE_E2E_GATEWAY_BINARY` points to one; the gateway is configured with a temporary route that forwards authentication to the spawned Hopae | Forward-auth, header-injection and path-scope cases; skipped (not failed) when the variable is absent |
| Live provider | The gateway layer with a real provider tenant; credentials are read from the private environment file at run time | G8 only; never in `cargo test` |

Mock provider requirements: authorization-code flow with PKCE and nonce,
discovery document, JWKS with key rotation, and switchable misbehavior (wrong
`state`, wrong `nonce`, expired token, mismatched `aud`, slow responses, invalid
signature, oversized responses). Every abuse case the mock can express must be
expressed there rather than left to manual testing.

### Coverage tracking

- `make scenario-coverage` prints a table: scenario, status, cases, mapped tests, missing tests, orphan tests. CI fails on missing or orphan entries for `approved` or later scenarios.
- `make coverage` runs `cargo llvm-cov` over unit and integration tests. Line coverage is a diagnostic, not a gate; scenario coverage is the gate.
- The roadmap lists scenario ranges per milestone; a milestone is complete when every scenario in its range is `verified-live` or explicitly marked `implemented` with the reason live verification is impossible.

## Branches, commits and worktrees

- `main` is always releasable. Work happens on short-lived branches named `<type>/<slug>` with types `feat`, `fix`, `sec`, `docs`, `test`, `refactor`, `chore`.
- Parallel work uses separate worktrees created from the current `main`; each worktree has one owner and one task brief.
- Integrate by rebasing onto `main` and fast-forwarding. No merge commits on `main`.
- Commit subjects are imperative, 72 characters or fewer, and say what changed from the operator's perspective. The body says why, what was verified and how.
- Trailers carry traceability. Use the ones that apply:

```text
Scenario: 012, 013
ADR: 0004
Threat-Model: updated
```

`Threat-Model:` is mandatory for every security-relevant change and takes
`updated`, `reviewed` (no change needed, reviewed) or `n/a`. Commits produced in
an assisted session also carry the session attribution trailer that the session
provides; it is appended last.

- One logical change per commit. Documentation in both languages, scenario, tests and code for one behavior belong to the same commit or the same reviewed series.
- Never commit secrets, generated artifacts, local configuration, internal documents or files that name internal infrastructure. The pre-commit hook and `make check-docs` reject them; the hook is a safety net, not the rule.

## Changelog and versioning

- `CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/): an `Unreleased` section and one section per version with `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- Every user-visible change adds an entry in the same commit. Security fixes always go under `Security`, even when they are also bug fixes.
- Versions follow [Semantic Versioning 2.0.0](https://semver.org/). Before 1.0.0, a minor version may contain breaking changes to configuration or the gateway contract; each one is listed under `Changed` with a migration note. Patch versions never break configuration.
- The configuration schema and the forward-authentication response contract are part of the public API for versioning purposes.

## Release and signing

The release process signs an Ed25519 manifest over the exact release artifact.
Hopae automatic self-update is not implemented yet; manifest verification is
performed during artifact staging. The planned updater uses this envelope,
in the same style as Hangang's signed updates and Sugyeol's GitHub release
discovery. The verification key is published in `release-public-key.txt`; the
signing seed is held offline by the maintainer and never enters the repository,
the build environment of the published binary, or any agent context. Details of
the envelope, discovery, downgrade protection and rollback are decided in a
dedicated ADR before milestone M6 and may refine this checklist.

Release checklist:

- [ ] `main` is green on G6 and the milestone's scenarios are `verified-live`.
- [ ] Version bumped in `Cargo.toml`; `CHANGELOG.md` `Unreleased` moved to the new version with the date.
- [ ] Threat model and configuration reference reflect the release.
- [ ] Annotated tag `vMAJOR.MINOR.PATCH` created on the release commit.
- [ ] Static binaries built per supported target with `--locked` from the tagged commit.
- [ ] Release assets prepared: raw executable per target, `<binary>-<target>.manifest.json` (signed envelope: version, target, artifact URL, SHA-256, size), `SHA256SUMS`.
- [ ] Manifest signed offline with the seed matching `release-public-key.txt`; signatures verified with the public key before upload.
- [ ] Executables uploaded first, manifests last; release marked stable (never draft or pre-release for an update-eligible release).
- [ ] Signatures and artifact hashes verified against `release-public-key.txt`; automatic self-update is a separate future feature, not a claim of this release.
- [ ] Deployment follows G9.

## Security rules

These rules apply to code, tests, documentation, commit messages, review
context files and task briefs.

- [ ] **No secrets in the repository, ever.** Tokens, client secrets, signing seeds, cookies and session keys come from a private environment file outside the repository (conventionally `~/env`) or from the deployment's secret store, read at run time. Their values are never written into source, fixtures, documentation, logs, test output or commit messages. Tests that need credentials read them from the environment and skip when absent.
- [ ] **No internal infrastructure in public artifacts.** Hostnames, internal domains, IP addresses, machine labels, deployment paths and account names of the operator's environment appear only under `internal/`. Public examples use loopback addresses and `*.example.test` names. The publication checker reads its denylist from a file outside the repository so the denylist itself is never published.
- [ ] **Threat model follows every security-relevant change.** Any change to authentication, session handling, cookies, headers consumed from or emitted to the gateway, cryptography, rate limiting, blacklists, admin access, webhooks, Lua hooks, update verification or storage of personal data updates `docs/THREAT_MODEL.md` in the same change and carries `Threat-Model: updated`.
- [ ] **Fail closed.** When a required check cannot run (store unavailable, clock skew beyond tolerance, provider unreachable), the request is denied, logged and counted. A missing dependency never degrades to "allow".
- [ ] **No custom cryptography.** Use audited crates; constant-time comparison for secrets; random values from the operating system CSPRNG; keys rotated through configuration, never through a message from the thing being verified.
- [ ] **Identity headers are owned by the gateway contract.** Hopae only emits identity to the gateway's authentication check; client-supplied copies of those headers are never trusted, and the contract documents how the gateway strips them.
- [ ] **Logs and audit records contain identifiers, not credentials.** Subject IDs, session IDs (hashed where they are bearer tokens), provider names, decision and reason codes — never tokens, passwords, codes or full cookies.
- [ ] **Dependencies are audited.** `cargo audit` runs in G6; new dependencies are justified in the commit body; `--locked` builds only.
- [ ] **Agents never scan credential stores.** Automated roles read only the files named in their task brief; they do not search process environments, token files or private directories to "find" a value.

## Make targets

The `Makefile` provides the following targets; gates refer to them by name.
Targets are created in milestone M0 and must keep these names.

| Target | Runs |
| --- | --- |
| `make check` | `cargo fmt --all -- --check`; `cargo clippy --all-targets --locked -- -D warnings` |
| `make test` | `cargo test --locked --all-targets` (unit and integration with the mock provider) |
| `make audit` | `cargo audit` |
| `make check-docs` | Link, navigation, heading, language-placement, translation-status and publication-policy checks over the Git index |
| `make scenario-coverage` | Scenario-to-test cross-check |
| `make gates` | `check`, `test`, `audit`, `check-docs`, `scenario-coverage` in order |
| `make e2e` | Gateway-layer scenarios; requires `HOPAE_E2E_GATEWAY_BINARY` |
| `make coverage` | `cargo llvm-cov` report |
| `make static` | Static Linux release build |
| `make release-assets` | Package binaries, manifests and `SHA256SUMS` for signing |

## Definition of done

A change is done when all of the following hold, in addition to every gate
having passed:

- [ ] The behavior exists in a scenario, and the scenario is `verified-live` or carries a recorded reason why live verification is impossible.
- [ ] The orchestrator personally re-ran at least one scenario case and one abuse case rather than relying on an implementer's report.
- [ ] English documentation and its Korean translation are updated in the same change and `make check-docs` passes.
- [ ] The threat model, configuration reference and CHANGELOG are updated.
- [ ] No S1 or S2 review finding is open; deferred S3 findings have scenarios.
- [ ] An operator can roll the change back with documented steps.
- [ ] No internal name, secret or generated artifact is in the diff.

Passing `make gates` with nothing else above is not done; it is ready for review.

Hopae artifact staging supports `tools/prepare_release.py --target TARGET --output OUTPUT
--signer OFFLINE_SIGNER --seed PRIVATE_SEED_FILE`. The seed must match the repository
public key. The signer uses the same exact-byte payload/base64-envelope scheme as
Sumunjang; staging independently verifies the signature, payload and artifact hash.
The private seed remains outside the repository and server deployment.
