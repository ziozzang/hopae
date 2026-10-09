# Tools

Repository tooling. Python 3 standard library only.

| File | Purpose |
| --- | --- |
| `check_docs.py` | Documentation checks, publication policy and scenario coverage |
| `check_boundary.py` | Gateway adapter boundary lint (ADR-0013) |
| `test_check_docs.py` | Unit tests for `check_docs.py` |

## Commands

```sh
make check-docs          # documentation + publication checks over the Git index
make check-boundary      # gateway wire names must stay inside src/gateway/
make scenario-coverage   # scenario case table <-> test functions
make tools-test          # python3 -m unittest tools/test_check_docs.py
```

### check-boundary

Fails when `x-original-`, `x-forwarded-` or `x-hangang` appears in any file
under `src/` outside `src/gateway/`; comments and strings count. `tests/` is
not scanned because gateway-layer tests legitimately name gateway headers.
`make check` runs it first; it needs no crate.

`check_docs.py` reads the Git index, so stage the intended changes first. Use
`--worktree` to walk the directory instead and `--only docs|publish` to run half.

### check-docs

Structural parity of each Korean translation with its source (heading levels,
fenced-block language tags, table row counts), `doc-rev`/`source-rev` agreement,
links and anchors, one H1 and no skipped levels, the navigation line, Korean
placement, and ADR/scenario conformance with their templates.

### Publication check

- Fails for tracked files under `internal/`, `TODO.md`, credential-style file
  names and secret-shaped strings.
- `HOPAE_PUBLISH_DENYLIST` names a file outside the repository, one regex or
  literal per line (`#` comments allowed). Unset: a warning, or a failure with
  `--require-denylist`. Set but unreadable: failure.
- `--env-file PATH` treats the values of `KEY=VALUE` lines (for example `~/env`)
  of 12 or more characters as literal secrets to find.
- Output never contains a secret value, matched line or denylist pattern; only
  `path:line`, the variable KEY or the denylist entry number.

### scenario-coverage

Reads `scenarios/NNN-*.md` (case headings and the Test mapping table) and every
`fn sNNN_...` under `tests/` and `src/`. Prints a table; fails on missing or
orphan tests for scenarios that are `approved` or later (warns for `draft`),
on names that do not start with the case prefix (`S012-A2` is `s012_a2_`), and
on tests whose scenario file does not exist. `live` cases are not looked up in
source.

## Pre-commit hook

```sh
git config core.hooksPath .githooks
```

The hook runs `gitleaks` on the staged changes when it is installed, then the
publication check with `--env-file ~/env` when that file exists. If
`HOPAE_PUBLISH_DENYLIST` is unset it uses `internal/publish-denylist.txt` when
present. It is a safety net; `make check-docs` is the rule.

## Make targets without a crate

`check`, `test`, `audit`, `coverage`, `static`, `e2e` and `release-assets`
print a `skip:` message while `Cargo.toml` is absent and run (failing on error)
once it exists. `make e2e` additionally requires `HOPAE_E2E_GATEWAY_BINARY`.
