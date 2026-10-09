#!/usr/bin/env python3
"""Unit tests for tools/check_docs.py. Run: python3 -m unittest tools/test_check_docs.py

Fixtures are built in temporary directories. Secret-shaped values are assembled
at run time so this file itself never contains one.
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_docs as cd  # noqa: E402

EN_PAGE = """# Sessions

<!-- doc-rev: 2 -->

[Documentation](README.md) · [한국어](ko/SESSIONS.md)

Sessions are stored server-side.

## Behavior

| Key | Value |
| --- | --- |
| a | b |

```yaml
ttl: 60
```

See [behavior](#behavior) and [the index](README.md#documentation).
"""

KO_PAGE = """# 세션

<!-- translation-status: source=../SESSIONS.md source-rev=2 status=current -->

[문서 목차](README.md) · [English](../SESSIONS.md)

세션은 서버 측에 저장됩니다.

## 동작

| 키 | 값 |
| --- | --- |
| a | b |

```yaml
ttl: 60
```

[동작](#동작)과 [목차](README.md#문서)를 참고하십시오.
"""

ADR = """# ADR-0002: Use opaque cookies

- Status: Accepted
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 001
- Threat model: n/a
- Supersedes: none

## Context

Facts.

## Decision

Hopae stores sessions server-side.

## Consequences

### Positive

- Good.

### Negative

- Bad.

### Neutral

- Follow-up.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A | b |

## Adversarial review

None yet.

## References

- RFC.

## 한국어 요약

불투명 쿠키를 사용합니다.
"""


def scenario(num="001", status="approved", mapping=None, extra_case=""):
    cats = "\n".join(f"| {c} | — | no: n/a |" for c in cd.ABUSE_CATEGORIES)
    mapping = mapping if mapping is not None else [
        (f"S{num}-1", f"s{num}_1_login", f"tests/scenarios/s{num}.rs", "integration", "planned"),
        (f"S{num}-A1", f"s{num}_a1_replay", f"tests/scenarios/s{num}.rs", "integration", "planned"),
    ]
    rows = "\n".join(f"| {m[0]} | `{m[1]}` | `{m[2]}` | {m[3]} | {m[4]} |" for m in mapping)
    return f"""# S{num} — Login works

<!-- scenario-status: {status} -->

- Area: core
- Milestone: M1
- ADRs: 0002
- Threat model: TM-01
- Gateway contract: n/a

## Goal

Goal.

## Preconditions and fixtures

- Fixture.

## Main flow

### S{num}-1 Login

- Given: x
- When: y
- Then: z
{extra_case}
## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
{cats}

### S{num}-A1 Replay

- Given: x

## Observability expectations

- Log.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
{rows}

## Live verification

None.

## Open questions

None.

## 한국어 요약

요약.
"""


class Repo:
    """A temporary directory holding a minimal valid documentation tree."""

    def __init__(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = self._td.name
        self.write("README.md", "# Hopae\n\n<!-- doc-rev: 1 -->\n\n[Documentation](docs/README.md) · [한국어](README.ko.md)\n\nText.\n")
        self.write("README.ko.md", "# Hopae\n\n<!-- translation-status: source=README.md source-rev=1 status=current -->\n\n[문서 목차](docs/ko/README.md) · [English](README.md)\n\n본문.\n")
        self.write("docs/README.md", "# Documentation\n\n<!-- doc-rev: 1 -->\n\n[한국어 목차](ko/README.md)\n\n## Documentation\n\n- [Sessions](SESSIONS.md)\n")
        self.write("docs/ko/README.md", "# 문서\n\n<!-- translation-status: source=../README.md source-rev=1 status=current -->\n\n[English](../README.md)\n\n## 문서\n\n- [세션](SESSIONS.md)\n")
        self.write("docs/SESSIONS.md", EN_PAGE)
        self.write("docs/ko/SESSIONS.md", KO_PAGE)
        self.write("docs/adr/0002-use-opaque-cookies.md", ADR)
        self.write("scenarios/001-login.md", scenario())

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def read(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8") as fh:
            return fh.read()

    def sub(self, rel, old, new):
        text = self.read(rel)
        self.assert_in(old, text)
        self.write(rel, text.replace(old, new, 1))

    @staticmethod
    def assert_in(old, text):
        assert old in text, f"fixture text {old!r} not found"

    def git_init(self):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        subprocess.run(["git", "init", "-q", self.root], check=True, env=env)
        return env

    def cleanup(self):
        self._td.cleanup()


class Base(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)

    def run_checks(self, publish=False, **kw):
        tree = cd.open_tree(self.repo.root, True)
        f = cd.Findings()
        cd.check_docs(tree, f)
        if publish:
            cd.check_publish(tree, f, **kw)
        return f

    def fails(self, f):
        return [t for l, t in f.items if l == "FAIL"]

    def assertFailsWith(self, f, needle):
        msgs = self.fails(f)
        self.assertTrue(any(needle in m for m in msgs), f"no FAIL containing {needle!r} in {msgs}")

    def assertClean(self, f):
        self.assertEqual(self.fails(f), [])


class TestDocsPass(Base):
    def test_valid_tree_passes(self):
        self.assertClean(self.run_checks())


class TestParity(Base):
    def test_heading_mismatch(self):
        self.repo.sub("docs/ko/SESSIONS.md", "## 동작\n", "### 동작\n")
        self.assertFailsWith(self.run_checks(), "heading levels differ")

    def test_fence_language_mismatch(self):
        self.repo.sub("docs/ko/SESSIONS.md", "```yaml", "```json")
        self.assertFailsWith(self.run_checks(), "fenced blocks")

    def test_table_rows_mismatch(self):
        self.repo.sub("docs/ko/SESSIONS.md", "| a | b |\n", "| a | b |\n| c | d |\n")
        self.assertFailsWith(self.run_checks(), "table row counts")

    def test_orphan_translation(self):
        self.repo.write("docs/ko/EXTRA.md", self.repo.read("docs/ko/SESSIONS.md"))
        self.assertFailsWith(self.run_checks(), "no English source")


class TestRevisions(Base):
    def test_source_rev_mismatch_fails(self):
        self.repo.sub("docs/SESSIONS.md", "doc-rev: 2", "doc-rev: 3")
        self.assertFailsWith(self.run_checks(), "source-rev 2 != doc-rev 3")

    def test_stale_warns_when_one_behind(self):
        self.repo.sub("docs/SESSIONS.md", "doc-rev: 2", "doc-rev: 3")
        self.repo.sub("docs/ko/SESSIONS.md", "status=current", "status=stale")
        f = self.run_checks()
        self.assertClean(f)
        self.assertTrue(any(l == "WARN" and "stale" in t for l, t in f.items))

    def test_stale_fails_when_source_bumps_again(self):
        self.repo.sub("docs/SESSIONS.md", "doc-rev: 2", "doc-rev: 4")
        self.repo.sub("docs/ko/SESSIONS.md", "status=current", "status=stale")
        self.assertFailsWith(self.run_checks(), "source bumped again")

    def test_missing_doc_rev(self):
        self.repo.sub("docs/SESSIONS.md", "<!-- doc-rev: 2 -->", "")
        self.assertFailsWith(self.run_checks(), "doc-rev marker")

    def test_wrong_source_path(self):
        self.repo.sub("docs/ko/SESSIONS.md", "source=../SESSIONS.md", "source=SESSIONS.md")
        self.assertFailsWith(self.run_checks(), "resolves to")


class TestLinks(Base):
    def test_broken_link(self):
        self.repo.sub("docs/SESSIONS.md", "(README.md#documentation)", "(MISSING.md)")
        self.assertFailsWith(self.run_checks(), "broken link")

    def test_missing_anchor_in_other_page(self):
        self.repo.sub("docs/SESSIONS.md", "README.md#documentation", "README.md#nope")
        self.assertFailsWith(self.run_checks(), "anchor")

    def test_missing_self_anchor(self):
        self.repo.sub("docs/SESSIONS.md", "(#behavior)", "(#absent)")
        self.assertFailsWith(self.run_checks(), "anchor #absent")

    def test_link_into_internal(self):
        self.repo.write("internal/x.md", "# x\n")
        self.repo.sub("docs/SESSIONS.md", "(README.md#documentation)", "(../internal/x.md)")
        self.assertFailsWith(self.run_checks(), "internal/")

    def test_code_span_and_fence_links_ignored(self):
        self.repo.sub("docs/SESSIONS.md", "ttl: 60", "ttl: 60\n[x](nowhere.md)")
        self.repo.sub("docs/SESSIONS.md", "Sessions are", "`[y](nowhere2.md)` Sessions are")
        self.repo.sub("docs/ko/SESSIONS.md", "ttl: 60", "ttl: 60\n[x](nowhere.md)")
        self.assertClean(self.run_checks())

    def test_directory_link_ok(self):
        self.repo.sub("docs/README.md", "(SESSIONS.md)", "(adr/)")
        self.assertClean(self.run_checks())


class TestStructureRules(Base):
    def test_two_h1(self):
        self.repo.sub("docs/SESSIONS.md", "## Behavior", "# Another")
        self.assertFailsWith(self.run_checks(), "exactly one H1")

    def test_skipped_level(self):
        self.repo.sub("docs/SESSIONS.md", "## Behavior", "#### Behavior")
        self.assertFailsWith(self.run_checks(), "skipped heading level")

    def test_missing_nav_line(self):
        self.repo.sub("docs/SESSIONS.md", "[Documentation](README.md) · [한국어](ko/SESSIONS.md)\n", "Plain.\n")
        self.assertFailsWith(self.run_checks(), "navigation line")

    def test_nav_missing_counterpart(self):
        self.repo.sub("docs/SESSIONS.md", " · [한국어](ko/SESSIONS.md)", "")
        self.assertFailsWith(self.run_checks(), "must link to docs/ko/SESSIONS.md")

    def test_ko_nav_missing_english(self):
        self.repo.sub("docs/ko/SESSIONS.md", " · [English](../SESSIONS.md)", "")
        self.assertFailsWith(self.run_checks(), "must link to docs/SESSIONS.md")

    def test_index_nav_counterpart(self):
        self.repo.sub("README.md", "[한국어](README.ko.md)", "[x](docs/README.md)")
        self.assertFailsWith(self.run_checks(), "README.ko.md")

    def test_extra_nesting_rejected(self):
        self.repo.write("docs/deep/x.md", "# X\n")
        self.assertFailsWith(self.run_checks(), "no other nesting")


class TestKoreanPlacement(Base):
    def test_korean_prose_in_english_page(self):
        self.repo.sub("docs/SESSIONS.md", "Sessions are stored", "세션은 Sessions are stored")
        self.assertFailsWith(self.run_checks(), "Korean prose")

    def test_korean_in_code_span_and_fence_allowed(self):
        self.repo.sub("docs/SESSIONS.md", "ttl: 60", "ttl: 60\n# 한국어 주석")
        self.repo.sub("docs/SESSIONS.md", "Sessions are", "Format `호패` Sessions are")
        self.assertClean(self.run_checks())

    def test_summary_section_allowed_only_in_adr_and_scenario(self):
        self.repo.sub("docs/SESSIONS.md", "## Behavior", "## 한국어 요약\n\n요약\n\n## Behavior")
        self.assertFailsWith(self.run_checks(), "Korean prose")

    def test_glossary_table_allowed(self):
        self.repo.write("docs/GLOSSARY.md", "# Glossary\n\n<!-- doc-rev: 1 -->\n\n[Documentation](README.md)\n\n| Term | 용어 |\n| --- | --- |\n| a | 가 |\n")
        self.assertClean(self.run_checks())

    def test_korean_in_adr_outside_summary(self):
        self.repo.sub("docs/adr/0002-use-opaque-cookies.md", "Facts.", "사실.")
        self.assertFailsWith(self.run_checks(), "Korean prose")


class TestTemplates(Base):
    def test_adr_missing_section(self):
        self.repo.sub("docs/adr/0002-use-opaque-cookies.md", "## Alternatives considered", "## Other")
        self.assertFailsWith(self.run_checks(), "Alternatives considered")

    def test_adr_bad_status_and_date(self):
        self.repo.sub("docs/adr/0002-use-opaque-cookies.md", "Status: Accepted", "Status: Maybe")
        self.repo.sub("docs/adr/0002-use-opaque-cookies.md", "2026-10-09", "today")
        f = self.run_checks()
        self.assertFailsWith(f, "Status must be")
        self.assertFailsWith(f, "Date must be")

    def test_adr_number_mismatch_and_filename(self):
        self.repo.sub("docs/adr/0002-use-opaque-cookies.md", "ADR-0002", "ADR-0009")
        self.assertFailsWith(self.run_checks(), "does not match filename")
        self.repo.write("docs/adr/bad_name.md", ADR)
        self.assertFailsWith(self.run_checks(), "NNNN-kebab-title.md")

    def test_adr_summary_must_be_last(self):
        p = "docs/adr/0002-use-opaque-cookies.md"
        self.repo.sub(p, "## References\n\n- RFC.\n\n", "")
        self.repo.write(p, self.repo.read(p) + "\n## References\n\n- RFC.\n")
        self.assertFailsWith(self.run_checks(), "must be the last section")

    def test_scenario_missing_category(self):
        self.repo.sub("scenarios/001-login.md", "| Enumeration | — | no: n/a |\n", "")
        self.assertFailsWith(self.run_checks(), "category 'Enumeration'")

    def test_scenario_bad_status(self):
        self.repo.sub("scenarios/001-login.md", "scenario-status: approved", "scenario-status: ready")
        self.assertFailsWith(self.run_checks(), "unknown scenario status")

    def test_scenario_missing_metadata(self):
        self.repo.sub("scenarios/001-login.md", "- Milestone: M1\n", "")
        self.assertFailsWith(self.run_checks(), "Milestone")

    def test_scenario_wrong_case_number(self):
        self.repo.sub("scenarios/001-login.md", "### S001-A1", "### S009-A1")
        self.assertFailsWith(self.run_checks(), "case S009-A1")

    def test_scenario_h1_mismatch(self):
        self.repo.sub("scenarios/001-login.md", "# S001 — Login", "# S002 — Login")
        self.assertFailsWith(self.run_checks(), "does not match filename")

    def test_scenario_bad_mapping_header(self):
        self.repo.sub("scenarios/001-login.md", "| Case | Test | File | Kind | Status |", "| Case | Name |")
        self.assertFailsWith(self.run_checks(), "Test mapping table")


class TestPublication(Base):
    def _secret(self, tag="alpha"):
        return "Zq9" + tag + "Kd7x" + "L2mN8pR4"  # 20+ chars, assembled at run time

    def test_denylist_literal_and_regex(self):
        dl = os.path.join(self.repo.root, "..", os.path.basename(self.repo.root) + ".deny")
        with open(dl, "w") as fh:
            fh.write("# comment\n\nhost-[0-9]+\\.corp\nsecret-literal.name\n")
        self.addCleanup(os.remove, dl)
        self.repo.sub("docs/SESSIONS.md", "Sessions are", "Sessions at host-42.corp are")
        f = self.run_checks(True, denylist_path=dl)
        self.assertFailsWith(f, "docs/SESSIONS.md:")
        self.assertFailsWith(f, "denylist entry #3")
        out = f.render()
        self.assertNotIn("host-42", out)
        self.assertNotIn("secret-literal", out)

    def test_denylist_clean_passes(self):
        dl = os.path.join(self.repo.root, "..", os.path.basename(self.repo.root) + ".deny")
        with open(dl, "w") as fh:
            fh.write("never-present-token\n")
        self.addCleanup(os.remove, dl)
        self.assertClean(self.run_checks(True, denylist_path=dl))

    def test_missing_denylist_file_fails(self):
        f = self.run_checks(True, denylist_path="/nonexistent/deny.txt")
        self.assertFailsWith(f, "cannot read denylist")

    def test_require_denylist(self):
        self.assertFailsWith(self.run_checks(True, require_denylist=True), "HOPAE_PUBLISH_DENYLIST")

    def test_unconfigured_denylist_only_warns(self):
        f = self.run_checks(True)
        self.assertClean(f)
        self.assertTrue(any(l == "WARN" for l, _ in f.items))

    def test_internal_tracked_fails(self):
        self.repo.write("internal/notes.txt", "x\n")
        self.assertFailsWith(self.run_checks(True), "internal/")

    def test_secret_shaped_strings(self):
        self.repo.write("docs/leak.txt", "key = " + "AKIA" + "ABCDEFGHIJKLMNOP" + "\n")
        self.repo.write("docs/leak2.txt", "-----BEGIN " + "RSA PRIVATE KEY-----\n")
        f = self.run_checks(True)
        self.assertFailsWith(f, "docs/leak.txt:1")
        self.assertFailsWith(f, "docs/leak2.txt:1")
        self.assertNotIn("ABCDEFGHIJKLMNOP", f.render())

    def test_forbidden_file_names(self):
        self.repo.write(".env", "A=b\n")
        self.repo.write(".env.example", "A=\n")
        f = self.run_checks(True)
        self.assertFailsWith(f, ".env:")
        self.assertFalse(any(t.startswith(".env.example") for t in self.fails(f)))

    def test_env_file_values_detected_and_redacted(self):
        secret = self._secret()
        envf = os.path.join(self.repo.root, "..", os.path.basename(self.repo.root) + ".envfile")
        with open(envf, "w") as fh:
            fh.write(f"# c\nMY_TOKEN={secret}\nexport QUOTED=\"{self._secret('beta')}\"\nSHORT=abc\nEMPTY=\n")
        self.addCleanup(os.remove, envf)
        self.repo.write("docs/notes.md", f"# N\n\nline\ntoken is {secret} here\n")
        self.repo.write("docs/other.txt", f"x {self._secret('beta')}\nSHORT abc\n")
        f = self.run_checks(True, env_file=envf)
        out = f.render()
        self.assertIn("docs/notes.md:4", out)
        self.assertIn("MY_TOKEN", out)
        self.assertIn("docs/other.txt:1", out)
        self.assertIn("QUOTED", out)
        self.assertNotIn("SHORT", out)  # values under 12 chars ignored
        self.assertNotIn(secret, out)
        self.assertNotIn(self._secret("beta"), out)

    def test_cli_output_never_contains_secret(self):
        secret = self._secret("gamma")
        envf = os.path.join(self.repo.root, "..", os.path.basename(self.repo.root) + ".envfile2")
        with open(envf, "w") as fh:
            fh.write(f"API_KEY={secret}\n")
        self.addCleanup(os.remove, envf)
        self.repo.write("docs/notes.md", f"# N\n\n{secret}\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = cd.main(["--root", self.repo.root, "--worktree", "--only", "publish",
                          "--env-file", envf])
        self.assertEqual(rc, 1)
        self.assertNotIn(secret, buf.getvalue())
        self.assertIn("API_KEY", buf.getvalue())

    def test_env_file_missing_fails_without_leak(self):
        f = self.run_checks(True, env_file="/nonexistent/env")
        self.assertFailsWith(f, "cannot read env file")

    def test_scans_git_index_not_worktree(self):
        env = self.repo.git_init()
        secret = self._secret("delta")
        envf = os.path.join(self.repo.root, "..", os.path.basename(self.repo.root) + ".envfile3")
        with open(envf, "w") as fh:
            fh.write(f"TOK={secret}\n")
        self.addCleanup(os.remove, envf)
        self.repo.write("docs/untracked.md", f"# U\n\n{secret}\n")  # not staged
        subprocess.run(["git", "-C", self.repo.root, "add", "README.md"], check=True, env=env)
        tree = cd.open_tree(self.repo.root, False)
        self.assertTrue(tree.use_git)
        f = cd.Findings()
        cd.check_publish(tree, f, env_file=envf)
        self.assertClean(f)
        subprocess.run(["git", "-C", self.repo.root, "add", "docs/untracked.md"], check=True, env=env)
        tree = cd.open_tree(self.repo.root, False)
        f = cd.Findings()
        cd.check_publish(tree, f, env_file=envf)
        self.assertFailsWith(f, "docs/untracked.md:3")
        # staged content is what counts: change the worktree copy afterwards
        self.repo.write("docs/untracked.md", "# clean\n")
        f = cd.Findings()
        cd.check_publish(cd.open_tree(self.repo.root, False), f, env_file=envf)
        self.assertFailsWith(f, "docs/untracked.md:3")


class TestScenarioCoverage(Base):
    def _run(self):
        buf = io.StringIO()
        rc = cd.scenario_coverage(self.repo.root, buf)
        return rc, buf.getvalue()

    def _tests(self, names, path="tests/scenarios/s001.rs"):
        self.repo.write(path, "".join(f"#[test]\nfn {n}() {{}}\n" for n in names))

    def test_pass(self):
        self._tests(["s001_1_login", "s001_a1_replay"])
        # tree is a plain directory here, so use worktree via tmp git-less open
        rc, out = self._run()
        self.assertEqual(rc, 0, out)

    def test_missing_test_fails_when_approved(self):
        self._tests(["s001_1_login"])
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("s001_a1_replay (not found)", out)

    def test_missing_ok_when_draft(self):
        self.repo.sub("scenarios/001-login.md", "scenario-status: approved", "scenario-status: draft")
        rc, out = self._run()
        self.assertEqual(rc, 0, out)
        self.assertIn("WARN", out)

    def test_orphan_test_fails(self):
        self._tests(["s001_1_login", "s001_a1_replay", "s001_9_surprise"])
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("orphan test: s001_9_surprise", out)

    def test_orphan_without_scenario_file(self):
        self._tests(["s001_1_login", "s001_a1_replay"])
        self._tests(["s777_1_ghost"], "src/x.rs")
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("s777_1_ghost", out)

    def test_unmapped_case_fails(self):
        self.repo.sub("scenarios/001-login.md", "| S001-A1 | `s001_a1_replay`", "| S001-A9 | `s001_a9_other`")
        self._tests(["s001_1_login", "s001_a9_other"])
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("S001-A1 (no mapped test)", out)

    def test_live_kind_not_required_in_source(self):
        self.repo.sub("scenarios/001-login.md", "| integration | planned |\n\n## Live", "| live | planned |\n\n## Live")
        self._tests(["s001_1_login"])
        rc, out = self._run()
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
