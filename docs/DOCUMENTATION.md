# Documentation system

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/DOCUMENTATION.md)

This document defines where Hopae documents live, how the two languages are
kept in step, how pages are written, and which documents every feature must
ship with. The [development process](PROCESS.md) refers to these rules at its
documentation gates.

## Layout

```text
README.md                     Product overview and entry points (English, canonical)
README.ko.md                  Korean translation of README.md
CHANGELOG.md                  Keep a Changelog; English only
LICENSE                       MIT
release-public-key.txt        Ed25519 verification key for signed releases (from M6)
docs/
  README.md                   English documentation index
  PROCESS.md                  Development process
  DOCUMENTATION.md            This document
  ROADMAP.md                  Milestones and scenario ranges
  THREAT_MODEL.md             Living threat model (from M0)
  <TOPIC>.md                  One reference page per capability, English canonical
  ko/
    README.md                 Korean documentation index
    <TOPIC>.md                Full Korean translation, same filename as the source
  adr/
    0000-template.md          ADR template
    NNNN-kebab-title.md       One record per decision; never renumbered
scenarios/
  README.md                   Numbering ranges and status legend
  000-template.md             Scenario template
  NNN-kebab-name.md           One executable specification per scenario
deploy/                       Portable deployment templates; operator copies stay local
internal/                     Not published (gitignored): roles and tooling, review
                              reports, deployment receipts, publication denylist
```

Rules for the layout:

- English reference pages live directly in `docs/`. Korean translations live in `docs/ko/` with the **same filename**. No other nesting.
- Filenames are stable identifiers. Rename a page only with a redirect stub left at the old name for one minor version.
- `internal/` and `TODO.md` are excluded by `.gitignore`. Nothing in a published file links into `internal/`; a public page may say "recorded internally" and no more.
- `docs/adr/` and `scenarios/` are English-only by design (see [Language rule](#language-rule)).

## Language rule

English is the source of truth. A Korean page is a **full translation** of its
English source, not a summary: every section, table, example, prerequisite,
failure case and limitation is preserved. A translation that cannot be kept
complete is removed and replaced by a link to the English page, never left
partial.

### Same-change rule

The English page and its existing Korean translation are updated in the same
commit or the same reviewed series. A change is not reviewable while the
translation lags.

### Translation-status header

Every English page under `docs/` and the root `README.md` carries a document
revision marker immediately after the H1:

```markdown
# Page title

<!-- doc-rev: 3 -->
```

Every Korean translation carries a status header in the same position:

```markdown
# 페이지 제목

<!-- translation-status: source=../PAGE.md source-rev=3 status=current -->
```

- `doc-rev` is a positive integer. Bump it whenever a change alters meaning: behavior, defaults, limits, commands, examples, structure. Typo and formatting fixes do not bump it.
- `source-rev` must equal the source's `doc-rev`. `make check-docs` fails when they differ while `status=current`.
- `status=stale` is permitted only for a `sec/` hotfix whose translation could not be completed in the same change. It must be cleared by the next change to either file; `make check-docs` warns on `stale` and fails when a stale translation's source bumps again.
- `source` is the relative path from the translation to its source.

### Exceptions

The following are English-only, with an optional short `## 한국어 요약` section
at the end for a Korean summary. They are exceptions because they are
developer-facing historical records or executable specifications whose value is
in their identifiers and precision, not in their prose:

- `docs/adr/*.md` — decisions are immutable once accepted; translating them would create a second record that cannot be kept authoritative.
- `scenarios/*.md` — test names, header names and status codes dominate; the Given/When/Then prose is short.
- `CHANGELOG.md` — release notes are English; Korean release notes, when written, go in the GitHub release description.

Language-switch links, the bilingual terminology table in `GLOSSARY.md`, and
quoted formats inside fenced blocks or inline code spans are the only other
places Korean text appears in English files. `make check-docs` rejects Korean
prose elsewhere in `docs/*.md`.

## Document types

| Type | Location | Purpose | Lifecycle |
| --- | --- | --- | --- |
| Reference page | `docs/<TOPIC>.md` (+ `ko/`) | Describes current behavior of one capability: configuration, behavior, failure modes, management surface, limits, verification | Updated with every change to the capability; describes what is, never what is planned |
| Configuration reference | `docs/CONFIG.md` (+ `ko/`) | Every configuration key, type, default, constraints, reload behavior | Updated in the same change as the key |
| Gateway contract | `docs/GATEWAY_CONTRACT.md` (+ `ko/`) | The exact request/response contract between the gateway's authentication check and Hopae: endpoints, headers, status codes, cookies, timeouts | Versioned with the product; changes are breaking before 1.0 only with a `Changed` entry and migration note |
| Threat model | `docs/THREAT_MODEL.md` (+ `ko/`) | Assets, trust boundaries, entry points, attacker capabilities, threats and the mitigations relied on, with pointers to scenarios | Delta in every security-relevant change |
| ADR | `docs/adr/NNNN-*.md` | One architecture decision with context, alternatives, consequences and its adversarial review | Proposed → Accepted → Superseded/Deprecated; never edited after acceptance except status and links |
| Scenario | `scenarios/NNN-*.md` | Executable specification: Given/When/Then, abuse cases, test mapping, live verification | draft → approved → implemented → verified-live |
| Roadmap | `docs/ROADMAP.md` (+ `ko/`) | Milestones, scope, exit criteria, scenario ranges | Updated when a milestone changes; completed items move to the CHANGELOG |
| Process | `docs/PROCESS.md`, this page | How work is done | Changed only through an ADR |
| Internal record | `internal/**` | Role/tool assignments, review context files and reports, deployment receipts, environment specifics, publication denylist | Never published |

## Style guide

Checklist for every page:

- [ ] One descriptive H1 in sentence case; no other H1.
- [ ] Immediately after the revision or status header, a navigation line: `[Documentation](README.md) · [한국어](ko/PAGE.md)` in English reference pages, `[문서 목차](README.md) · [English](../PAGE.md)` in Korean ones. Index pages and root READMEs link to each other; ADRs and scenarios follow their templates instead.
- [ ] First paragraph states the capability and its scope in plain terms.
- [ ] Reference pages use this section order; omit empty sections rather than padding them:
  1. Prerequisites and configuration
  2. Behavior, including reload, failure and timeout behavior
  3. Management API, console and observability
  4. Limitations and compatibility
  5. Examples, verification and related pages
- [ ] H2 for major sections, H3 only inside an H2, no skipped levels.
- [ ] Tables for comparable options; fenced blocks with a language tag for commands, JSON, YAML, HTTP and code.
- [ ] Commands run from the repository root unless stated; a configuration fragment is labeled as a fragment.
- [ ] Describe current behavior. State limits as present boundaries ("Sessions are instance-local"), not as tasks ("TODO: share sessions").
- [ ] Say what the operator gains and link to the page that owns the contract; do not repeat a contract on several pages.
- [ ] Identifiers never change across languages: configuration keys, header names, API paths, flags, metric names, error codes, scenario and ADR IDs.
- [ ] Examples use loopback addresses and reserved names (`*.example.test`). Never a production host, internal domain, IP, deployment path or account.
- [ ] No secrets, not even obviously fake-looking ones that match a real format; use `<redacted>` placeholders.
- [ ] Korean prose uses the polite, direct `합니다체` register, consistent terminology from `GLOSSARY.md`, and keeps the source's sentence boundaries where natural. Translate headings; keep code, keys and values untouched; fix relative links for the `ko/` directory.
- [ ] Claims about other products name the scope, link to official sources and record the review date.

## Required documents per feature

A feature (roadmap item, new provider, new policy, new endpoint) is not
mergeable without every row that applies. "Applies" is decided at G1 and
recorded in the task brief.

| Document | Required when | Where |
| --- | --- | --- |
| Reference page (English + Korean) | Any operator- or user-visible behavior | `docs/<TOPIC>.md`, `docs/ko/<TOPIC>.md` |
| Configuration reference entry (English + Korean) | Any new or changed configuration key, environment variable or flag | `docs/CONFIG.md`, `docs/ko/CONFIG.md` |
| Gateway contract update (English + Korean) | Any change to headers, status codes, cookies or endpoints the gateway sees | `docs/GATEWAY_CONTRACT.md`, `docs/ko/GATEWAY_CONTRACT.md` |
| Threat-model delta (English + Korean) | Any security-relevant change, as defined in the [security rules](PROCESS.md#security-rules) | `docs/THREAT_MODEL.md`, `docs/ko/THREAT_MODEL.md` |
| Scenario(s) | Always | `scenarios/NNN-*.md` |
| ADR | Any decision that changes an interface, trust boundary, data model or guarantee | `docs/adr/NNNN-*.md` |
| CHANGELOG entry | Any user-visible change | `CHANGELOG.md` under `Unreleased` |
| Roadmap update | Scope or ordering of a milestone changed | `docs/ROADMAP.md`, `docs/ko/ROADMAP.md` |
| Deployment template update | Any new runtime dependency, port, volume or environment variable | `deploy/` |

## Validation

Stage the intended changes, then run:

```sh
make check-docs
git diff --cached --check
```

`make check-docs` reads the Git index, so ignored local files cannot hide a
broken published link. It checks:

- Local link targets exist (including anchors within the repository).
- Every reference page (`docs/*.md`, `docs/ko/*.md`) has one H1, no skipped heading levels, and the navigation line to its index; ADRs and scenarios are checked for one H1 and heading order only.
- Korean prose appears only in `docs/ko/`, root `README.ko.md`, the glossary table, language-switch labels, and `## 한국어 요약` sections of ADRs and scenarios.
- `doc-rev` / `source-rev` agreement and `status` rules described above.
- Structural parity between a translation and its source: same heading levels in the same order, same number of fenced blocks with the same language tags, same table row counts.
- Publication policy: no file under `internal/`, no secret-shaped strings, no entry from the publication denylist (read from a file outside the repository, path given by `HOPAE_PUBLISH_DENYLIST`, with the pre-commit hook passing it automatically when present).

Structural parity does not prove a faithful translation; a reviewer reads both
languages whenever examples, defaults or failure behavior change. The checker
does not validate external URLs or run commands against a server.
