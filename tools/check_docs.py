#!/usr/bin/env python3
"""Documentation, publication-policy and scenario-coverage checks for Hopae.

Implements the checks listed in docs/DOCUMENTATION.md (Validation) and
docs/PROCESS.md (Make targets). Python 3 standard library only.

Usage:
    check_docs.py [--root DIR] [--worktree] [--only docs|publish]
                  [--env-file PATH] [--denylist PATH] [--require-denylist]
    check_docs.py scenario-coverage [--root DIR]

By default the file set is the Git index (`git ls-files`), so ignored local
files cannot hide a broken published link. `--worktree` walks the directory
instead (used by tests and outside a Git checkout).

Secrets policy: this tool NEVER prints a secret value, a matched line or a
denylist pattern. Findings carry only `path:line`, a rule name, a variable KEY
name or a denylist entry number.

Exit status: 0 when no FAIL finding, 1 otherwise, 2 on usage errors.
"""
from __future__ import annotations

import argparse
import os
import posixpath
import re
import subprocess
import sys

HANGUL = re.compile(r"[ㄱ-ㆎ가-힣]")
FENCE = re.compile(r"^\s*(```+|~~~+)(.*)$")
HEADING = re.compile(r"^(#{1,6}) +(.+?)\s*#*\s*$")
DOC_REV = re.compile(r"^<!-- doc-rev: (\d+) -->\s*$")
TRANS = re.compile(
    r"^<!-- translation-status: source=(\S+) source-rev=(\d+) status=(\w+) -->\s*$"
)
SCEN_STATUS = re.compile(r"^<!-- scenario-status: ([a-z-]+) -->\s*$")
SCENARIO_STATUSES = {"draft", "approved", "implemented", "verified-live", "withdrawn"}
ENFORCED = {"approved", "implemented", "verified-live"}
SCENARIO_AREAS = {
    "core", "sessions", "providers", "management", "lua", "webhooks", "2fa",
    "lifecycle", "scale-out", "security",
}
ABUSE_CATEGORIES = [
    "Replay", "Tampering", "Race / timing", "Resource exhaustion",
    "Confused deputy", "Spoofed or duplicated headers", "Downgrade", "Enumeration",
]
INDEX_PAIRS = {
    "README.md": "README.ko.md",
    "README.ko.md": "README.md",
    "docs/README.md": "docs/ko/README.md",
    "docs/ko/README.md": "docs/README.md",
}
MIN_SECRET_LEN = 12

# Secret-shaped strings. Names are reported, matched text never is.
SECRET_PATTERNS = [
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]
FORBIDDEN_NAME = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks|sqlite3?|db))$"
)
ALLOWED_NAME = re.compile(r"(^|/)\.env\.example$")


class Findings:
    def __init__(self):
        self.items = []  # (level, text)

    def fail(self, where, msg):
        self.items.append(("FAIL", f"{where}: {msg}"))

    def warn(self, where, msg):
        self.items.append(("WARN", f"{where}: {msg}"))

    def failed(self):
        return any(l == "FAIL" for l, _ in self.items)

    def render(self):
        return "\n".join(f"{l} {t}" for l, t in self.items)


# --------------------------------------------------------------------------
# File sources
# --------------------------------------------------------------------------
class Tree:
    """The set of files to check: the Git index, or a directory walk."""

    def __init__(self, root, use_git):
        self.root = root
        self.use_git = use_git
        self._blobs = {}
        if use_git:
            out = subprocess.run(
                ["git", "-C", root, "ls-files", "-s", "-z"],
                check=True, capture_output=True,
            ).stdout.decode("utf-8", "surrogateescape")
            for rec in filter(None, out.split("\0")):
                meta, _, path = rec.partition("\t")
                parts = meta.split()
                if parts and parts[0] != "160000":  # skip submodules
                    self._blobs[path] = parts[1]
            self.paths = sorted(self._blobs)
        else:
            paths = []
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if d not in (".git", "target", "node_modules")]
                for f in fn:
                    paths.append(os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/"))
            self.paths = sorted(paths)
        self._set = set(self.paths)
        self._dirs = {p.rsplit("/", 1)[0] for p in self.paths if "/" in p}
        for d in list(self._dirs):
            while "/" in d:
                d = d.rsplit("/", 1)[0]
                self._dirs.add(d)

    def exists(self, path):
        return path in self._set or path in self._dirs

    def is_file(self, path):
        return path in self._set

    def read_bytes(self, path):
        if self.use_git:
            return subprocess.run(
                ["git", "-C", self.root, "cat-file", "blob", self._blobs[path]],
                check=True, capture_output=True,
            ).stdout
        with open(os.path.join(self.root, path), "rb") as fh:
            return fh.read()

    def read(self, path):
        return self.read_bytes(path).decode("utf-8", "replace")


def open_tree(root, force_worktree):
    root = os.path.abspath(root)
    if not force_worktree:
        r = subprocess.run(
            ["git", "-C", root, "rev-parse", "--show-toplevel"],
            capture_output=True,
        )
        if r.returncode == 0 and os.path.samefile(r.stdout.decode().strip(), root):
            return Tree(root, True)
    return Tree(root, False)


# --------------------------------------------------------------------------
# Markdown helpers
# --------------------------------------------------------------------------
def md_lines(content):
    """Yield (lineno, line, in_fence); fence delimiter lines have in_fence=None."""
    fence = None
    for i, line in enumerate(content.splitlines(), 1):
        m = FENCE.match(line)
        if m:
            if fence is None:
                fence = m.group(1)[0]
                yield i, line, None
                continue
            if m.group(1)[0] == fence and not m.group(2).strip():
                fence = None
                yield i, line, None
                continue
        yield i, line, fence is not None


def headings(content):
    """List of (lineno, level, text) outside fences."""
    out = []
    for i, line, infence in md_lines(content):
        if infence is None or infence:
            continue
        m = HEADING.match(line)
        if m:
            out.append((i, len(m.group(1)), m.group(2).strip()))
    return out


def slug(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").replace("*", "").lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors_of(content):
    seen, out = {}, set()
    for _, _, text in headings(content):
        s = slug(text)
        n = seen.get(s, 0)
        out.add(s if n == 0 else f"{s}-{n}")
        seen[s] = n + 1
    return out


def structure(content):
    """(heading levels, fence language tags, table row counts)."""
    levels, fences, tables = [], [], []
    rows = 0
    open_lang = None
    for _, line, infence in md_lines(content):
        if infence is None:
            if open_lang is None:
                open_lang = FENCE.match(line).group(2).strip()
            else:
                fences.append(open_lang)
                open_lang = None
            if rows:
                tables.append(rows)
                rows = 0
            continue
        if infence:
            continue
        m = HEADING.match(line)
        if m:
            levels.append(len(m.group(1)))
        if line.lstrip().startswith("|"):
            rows += 1
        elif rows:
            tables.append(rows)
            rows = 0
    if rows:
        tables.append(rows)
    return levels, fences, tables


def header_lines(content):
    """Return (h1_lineno, marker_line, marker_text, nav_lineno, nav_text)."""
    lines = content.splitlines()
    h1 = next((i for i, l in enumerate(lines) if l.startswith("# ")), None)
    if h1 is None:
        return None, None, None, None, None
    idx = [i for i in range(h1 + 1, len(lines)) if lines[i].strip()][:2]
    marker = (idx[0] + 1, lines[idx[0]]) if idx else (None, None)
    nav = (idx[1] + 1, lines[idx[1]]) if len(idx) > 1 else (None, None)
    return h1 + 1, marker[0], marker[1], nav[0], nav[1]


def link_targets(line):
    line = re.sub(r"`[^`]*`", "", line)
    for m in re.finditer(r"\]\(\s*<?([^)\s>]+)>?(?:\s+[^)]*)?\)", line):
        yield m.group(1)


def resolve(base, target):
    return posixpath.normpath(posixpath.join(posixpath.dirname(base), target))


def is_korean_side(p):
    return p == "README.ko.md" or p.startswith("docs/ko/")


# --------------------------------------------------------------------------
# Documentation checks
# --------------------------------------------------------------------------
def classify(p):
    if p.startswith("docs/adr/"):
        return "adr"
    if p.startswith("scenarios/"):
        return "scenario"
    if p == "CHANGELOG.md":
        return "changelog"
    if is_korean_side(p):
        return "ko-index" if p in INDEX_PAIRS else "ko-ref"
    if p in INDEX_PAIRS:
        return "en-index"
    if re.fullmatch(r"docs/[^/]+\.md", p):
        return "en-ref"
    if p.startswith("docs/"):
        return "other-docs"
    return "other"


def check_docs(tree, f):
    # Preserve upstream documentation verbatim; Hopae patch notes remain checked.
    upstream_docs = {"vendor/ldap3/README.md", "vendor/ldap3/CHANGELOG.md", "vendor/ldap3/LDAP-primer.md"}
    mds = [p for p in tree.paths if p.endswith(".md") and p != "TODO.md" and p not in upstream_docs]
    content = {p: tree.read(p) for p in mds}
    kind = {p: classify(p) for p in mds}

    for p in mds:
        if kind[p] == "other-docs":
            f.fail(p, "docs/ allows only docs/*.md, docs/ko/*.md and docs/adr/*.md (no other nesting)")

    check_headings(mds, content, kind, f)
    check_headers_and_nav(mds, content, kind, tree, f)
    check_pairs(mds, content, kind, f)
    check_links(mds, content, tree, f)
    check_korean_placement(mds, content, kind, f)
    check_adrs([p for p in mds if kind[p] == "adr"], content, f)
    check_scenarios([p for p in mds if kind[p] == "scenario"], content, f)
    return len(mds)


def check_headings(mds, content, kind, f):
    for p in mds:
        hs = headings(content[p])
        n1 = sum(1 for _, l, _ in hs if l == 1)
        if n1 != 1:
            f.fail(p, f"expected exactly one H1, found {n1}")
        prev = 0
        for ln, lvl, text in hs:
            if lvl > prev + 1:
                f.fail(f"{p}:{ln}", f"skipped heading level (H{prev} to H{lvl}) at '{text}'")
            prev = lvl


def check_headers_and_nav(mds, content, kind, tree, f):
    for p in mds:
        k = kind[p]
        if k not in ("en-ref", "en-index", "ko-ref", "ko-index"):
            continue
        h1, mline, mtext, nline, ntext = header_lines(content[p])
        if h1 is None:
            continue  # reported by the H1 check
        english = k.startswith("en-")
        want = "doc-rev" if english else "translation-status"
        ok = mtext is not None and (DOC_REV if english else TRANS).match(mtext)
        if not ok:
            f.fail(p, f"line after the H1 must be the {want} marker (docs/DOCUMENTATION.md, Translation-status header)")
        elif english and int(DOC_REV.match(mtext).group(1)) < 1:
            f.fail(f"{p}:{mline}", "doc-rev must be a positive integer")
        if ntext is None or not ntext.lstrip().startswith("["):
            f.fail(p, "missing navigation line after the revision/status header")
            continue
        targets = {resolve(p, t.partition("#")[0]) for t in link_targets(ntext) if t.partition("#")[0]}
        if k.endswith("index"):
            need = [INDEX_PAIRS[p]]
        else:
            name = posixpath.basename(p)
            if english:
                need = ["docs/README.md"]
                if tree.is_file(f"docs/ko/{name}"):
                    need.append(f"docs/ko/{name}")
            else:
                need = ["docs/ko/README.md", f"docs/{name}"]
        for n in need:
            if n not in targets:
                f.fail(f"{p}:{nline}", f"navigation line must link to {n}")


def check_pairs(mds, content, kind, f):
    sources = {p for p in mds if kind[p] in ("en-ref", "en-index")}
    claimed = set()
    for en in sorted(sources):
        if en == "README.md":
            ko = "README.ko.md"
        else:
            ko = "docs/ko/" + posixpath.basename(en)
        if ko not in content:
            continue
        claimed.add(ko)
        e, k = content[en], content[ko]
        se, sk = structure(e), structure(k)
        for name, a, b in zip(("heading levels", "fenced blocks (language tags)", "table row counts"), se, sk):
            if a != b:
                f.fail(ko, f"structural parity with {en}: {name} differ (en={a} ko={b})")
        rev = next((DOC_REV.match(l) for l in e.splitlines() if DOC_REV.match(l)), None)
        st = next((TRANS.match(l) for l in k.splitlines() if TRANS.match(l)), None)
        if not rev:
            f.fail(en, "missing doc-rev marker")
        if not st:
            f.fail(ko, "missing translation-status marker")
        if rev and st:
            src, srev, status = st.group(1), int(st.group(2)), st.group(3)
            drev = int(rev.group(1))
            if resolve(ko, src) != en:
                f.fail(ko, f"source={src} resolves to {resolve(ko, src)}, expected {en}")
            if status == "current":
                if srev != drev:
                    f.fail(ko, f"source-rev {srev} != doc-rev {drev} of {en} while status=current")
            elif status == "stale":
                if drev > srev + 1:
                    f.fail(ko, f"stale translation but source bumped again (doc-rev {drev}, source-rev {srev})")
                else:
                    f.warn(ko, "translation status is stale; clear it in the next change")
            else:
                f.fail(ko, f"unknown translation status '{status}' (expected current or stale)")
    for p in mds:
        if kind[p] in ("ko-ref", "ko-index") and p not in claimed:
            f.fail(p, "Korean page has no English source with the same filename")


def check_links(mds, content, tree, f):
    anchors = {}

    def anchor_set(p):
        if p not in anchors:
            anchors[p] = anchors_of(content[p]) if p in content else set()
        return anchors[p]

    for p in mds:
        for i, line, infence in md_lines(content[p]):
            if infence is None or infence:
                continue
            for target in link_targets(line):
                if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", target):
                    continue
                path, _, frag = target.partition("#")
                if not path:
                    if frag and frag not in anchor_set(p):
                        f.fail(f"{p}:{i}", f"anchor #{frag} not found in this page")
                    continue
                res = resolve(p, path)
                if res.startswith("../") or res == "..":
                    f.fail(f"{p}:{i}", f"link {target} leaves the repository")
                elif res == "internal" or res.startswith("internal/"):
                    f.fail(f"{p}:{i}", "published file links into internal/")
                elif not tree.exists(res.rstrip("/")):
                    f.fail(f"{p}:{i}", f"broken link {target} (not in the checked file set)")
                elif frag and res.endswith(".md") and res in content:
                    if frag not in anchor_set(res):
                        f.fail(f"{p}:{i}", f"anchor {target} not found in {res}")


def check_korean_placement(mds, content, kind, f):
    for p in mds:
        if is_korean_side(p):
            continue
        in_summary = False
        _, _, _, nav_ln, _ = header_lines(content[p])
        for i, line, infence in md_lines(content[p]):
            if infence is None or infence:
                continue
            m = HEADING.match(line)
            if m:
                in_summary = kind[p] in ("adr", "scenario") and m.group(2).strip() == "한국어 요약"
                if in_summary:
                    continue
            if in_summary or i == nav_ln:
                continue
            if posixpath.basename(p) == "GLOSSARY.md" and line.lstrip().startswith("|"):
                continue
            text = re.sub(r"`[^`]*`", "", line)
            text = re.sub(r"<!--.*?-->", "", text)
            if HANGUL.search(text):
                f.fail(f"{p}:{i}", "Korean prose outside docs/ko/, README.ko.md, glossary table or a 한국어 요약 section")


# --------------------------------------------------------------------------
# ADR and scenario template conformance
# --------------------------------------------------------------------------
def sections(content):
    """H2 titles in order, and H3 titles keyed by their H2."""
    h2, h3 = [], {}
    cur = None
    for _, lvl, text in headings(content):
        if lvl == 2:
            h2.append(text)
            cur = text
        elif lvl == 3 and cur:
            h3.setdefault(cur, []).append(text)
    return h2, h3


def check_order(p, got, required, optional_last, f):
    pos = []
    for r in required:
        if r not in got:
            f.fail(p, f"missing required section '## {r}'")
        else:
            pos.append(got.index(r))
    if pos != sorted(pos):
        f.fail(p, "sections out of template order")
    extra = [g for g in got if g not in required and g not in optional_last]
    if extra:
        f.warn(p, f"sections not in the template: {', '.join(extra)}")
    for o in optional_last:
        if o in got and got.index(o) != len(got) - 1:
            f.fail(p, f"'## {o}' must be the last section")


def meta(content, key):
    m = re.search(rf"^- {re.escape(key)}:[ \t]*(.*)$", content, re.M)
    return m.group(1).strip() if m else None


def check_adrs(paths, content, f):
    seen = {}
    for p in paths:
        name = posixpath.basename(p)
        c = content[p]
        m = re.fullmatch(r"(\d{4})-([a-z0-9]+(?:-[a-z0-9]+)*)\.md", name)
        if not m:
            f.fail(p, "ADR filename must be NNNN-kebab-title.md")
            continue
        num = m.group(1)
        if num in seen:
            f.fail(p, f"duplicate ADR number {num} (also {seen[num]})")
        seen[num] = p
        h1 = next((t for _, l, t in headings(c) if l == 1), "")
        hm = re.fullmatch(r"ADR-(\d{4}): (.+)", h1)
        if not hm:
            f.fail(p, "H1 must read 'ADR-NNNN: Title'")
        elif hm.group(1) != num:
            f.fail(p, f"H1 number ADR-{hm.group(1)} does not match filename {num}")
        template = num == "0000"  # placeholders in Status/Date are expected
        status = meta(c, "Status")
        if not template and (status is None or not re.fullmatch(
            r"(Proposed|Accepted|Deprecated|Superseded by ADR-\d{4}.*)", status
        )):
            f.fail(p, "Status must be Proposed, Accepted, Deprecated or 'Superseded by ADR-NNNN'")
        date = meta(c, "Date")
        if not template and (date is None or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)):
            f.fail(p, "Date must be YYYY-MM-DD")
        elif template and not date:
            f.fail(p, "missing metadata line '- Date:'")
        for key in ("Deciders", "Scenarios", "Threat model", "Supersedes"):
            if not meta(c, key):
                f.fail(p, f"missing metadata line '- {key}:'")
        h2, h3 = sections(c)
        check_order(p, h2, ["Context", "Decision", "Consequences", "Alternatives considered",
                            "Adversarial review", "References"], ["한국어 요약"], f)
        for sub in ("Positive", "Negative", "Neutral"):
            if sub not in h3.get("Consequences", []):
                f.fail(p, f"'## Consequences' needs '### {sub}'")


def check_scenarios(paths, content, f):
    seen = {}
    for p in paths:
        name = posixpath.basename(p)
        if name == "README.md":
            continue
        c = content[p]
        m = re.fullmatch(r"(\d{3})-([a-z0-9]+(?:-[a-z0-9]+)*)\.md", name)
        if not m:
            f.fail(p, "scenario filename must be NNN-kebab-name.md")
            continue
        num = m.group(1)
        template = num == "000"
        if num in seen:
            f.fail(p, f"duplicate scenario number {num} (also {seen[num]})")
        seen[num] = p
        h1 = next((t for _, l, t in headings(c) if l == 1), "")
        hm = re.match(r"S(\d{3}) — .+", h1)
        if not hm:
            f.fail(p, "H1 must read 'SNNN — Title'")
        elif hm.group(1) != num:
            f.fail(p, f"H1 number S{hm.group(1)} does not match filename {num}")
        _, _, mtext, _, _ = header_lines(c)
        sm = SCEN_STATUS.match(mtext or "")
        if not sm:
            f.fail(p, "line after the H1 must be '<!-- scenario-status: STATUS -->'")
        elif sm.group(1) not in SCENARIO_STATUSES:
            f.fail(p, f"unknown scenario status '{sm.group(1)}'")
        for key in ("Area", "Milestone", "ADRs", "Threat model", "Gateway contract"):
            if not meta(c, key):
                f.fail(p, f"missing metadata line '- {key}:'")
        if not template:
            area = meta(c, "Area") or ""
            bad = [a.strip() for a in area.split(",") if a.strip() not in SCENARIO_AREAS]
            if bad:
                f.fail(p, f"Area must be from {sorted(SCENARIO_AREAS)}")
            ms = meta(c, "Milestone") or ""
            if not re.fullmatch(r"M\d+(\s*[,-]\s*M\d+)*", ms):
                f.fail(p, "Milestone must look like M1")
        h2, h3 = sections(c)
        required = ["Goal", "Preconditions and fixtures", "Main flow"]
        tail = ["Abuse cases", "Observability expectations", "Test mapping",
                "Live verification", "Open questions"]
        got = [g for g in h2]
        optional_mid = "Alternative flows"
        order = required + ([optional_mid] if optional_mid in got else []) + tail
        check_order(p, got, order, ["한국어 요약"], f)
        # case headings carry this scenario's number
        for ln, lvl, text in headings(c):
            cm = re.match(r"S(\d{3})-([A-Za-z]?\d+)\b", text)
            if lvl == 3 and cm and cm.group(1) != num:
                f.fail(f"{p}:{ln}", f"case S{cm.group(1)}-{cm.group(2)} in scenario {num}")
        if "Main flow" in h2 and not any(
            re.match(rf"S{num}-\d+", t) for t in h3.get("Main flow", [])
        ):
            f.fail(p, f"'## Main flow' needs at least one '### S{num}-N' case")
        # abuse-case categories
        ab = table_rows(c, "Abuse cases")
        cats = [r[0] for r in ab[1:]] if ab else []
        for cat in ABUSE_CATEGORIES:
            if cat not in cats:
                f.fail(p, f"abuse-case table lacks category '{cat}'")
        # test-mapping header
        tm = table_rows(c, "Test mapping")
        if not tm or [x.lower() for x in tm[0]] != ["case", "test", "file", "kind", "status"]:
            f.fail(p, "Test mapping table must have columns Case | Test | File | Kind | Status")


def table_rows(content, h2_title):
    """Rows (list of cells) of the first table under the given H2; header first, divider dropped."""
    rows, active, started = [], False, False
    for _, line, infence in md_lines(content):
        if infence is None or infence:
            continue
        m = HEADING.match(line)
        if m:
            if active and started:
                break
            active = len(m.group(1)) == 2 and m.group(2).strip() == h2_title
            continue
        if not active:
            continue
        if line.lstrip().startswith("|"):
            started = True
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                continue
            rows.append(cells)
        elif started and line.strip():
            break
    return rows


# --------------------------------------------------------------------------
# Publication policy
# --------------------------------------------------------------------------
def load_denylist(path, f):
    entries = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        f.fail("publication", f"cannot read denylist file ({type(e).__name__})")
        return None
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            rx = re.compile(s, re.I)
        except re.error:
            rx = re.compile(re.escape(s), re.I)
        entries.append((n, rx))
    return entries


def load_env_secrets(path, f):
    """[(KEY, value)] with values >= MIN_SECRET_LEN chars. Values are never printed."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        f.fail("publication", f"cannot read env file ({type(e).__name__})")
        return None
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        s = re.sub(r"^export\s+", "", s)
        key, eq, val = s.partition("=")
        if not eq:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        if len(val) >= MIN_SECRET_LEN:
            out.append((key.strip(), val))
    return out


def check_publish(tree, f, denylist_path=None, env_file=None, require_denylist=False):
    entries = None
    if denylist_path:
        entries = load_denylist(denylist_path, f)
    elif require_denylist:
        f.fail("publication", "HOPAE_PUBLISH_DENYLIST is not set (denylist required)")
    else:
        f.warn("publication", "no denylist configured (set HOPAE_PUBLISH_DENYLIST); denylist scan skipped")
    secrets = (load_env_secrets(env_file, f) if env_file else []) or []

    for p in tree.paths:
        if p == "internal" or p.startswith("internal/"):
            f.fail(p, "file under internal/ must never be tracked or published")
            continue
        if p == "TODO.md":
            f.fail(p, "TODO.md is internal and must not be tracked")
        if FORBIDDEN_NAME.search(p) and not ALLOWED_NAME.search(p):
            f.fail(p, "credential or local-state file name must not be tracked")
        for n, rx in entries or []:
            if rx.search(p):
                f.fail(p, f"path matches publication denylist entry #{n}")
        try:
            text = tree.read(p)
        except (OSError, subprocess.CalledProcessError):
            f.fail(p, "unreadable while scanning")
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for name, rx in SECRET_PATTERNS:
                if rx.search(line):
                    f.fail(f"{p}:{i}", f"secret-shaped string ({name})")
            for key, val in secrets:
                if val in line:
                    f.fail(f"{p}:{i}", f"contains the value of env variable {key}")
            for n, rx in entries or []:
                if rx.search(line):
                    f.fail(f"{p}:{i}", f"matches publication denylist entry #{n}")


# --------------------------------------------------------------------------
# Scenario coverage
# --------------------------------------------------------------------------
TEST_FN = re.compile(r"\bfn\s+(s\d{3}_[a-z0-9]+_[A-Za-z0-9_]*)\s*\(")


def scenario_coverage(root, out=sys.stdout):
    """Scenario-to-test cross-check. Returns exit status."""
    tree = open_tree(root, False)
    f = Findings()
    scenarios = {}
    for p in tree.paths:
        m = re.fullmatch(r"scenarios/(\d{3})-[a-z0-9-]+\.md", p)
        if not m or m.group(1) == "000":
            continue
        c = tree.read(p)
        _, _, mtext, _, _ = header_lines(c)
        sm = SCEN_STATUS.match(mtext or "")
        status = sm.group(1) if sm else "unknown"
        cases = [cm.group(1).upper() for _, lvl, t in headings(c) if lvl == 3
                 for cm in [re.match(r"(S\d{3}-[A-Za-z]?\d+)\b", t)] if cm]
        mapping = []  # (case, test, file, kind)
        rows = table_rows(c, "Test mapping")
        for r in rows[1:]:
            if len(r) >= 4:
                mapping.append((r[0].upper(), r[1].strip("` "), r[2].strip("` "), r[3].strip("` ").lower()))
        scenarios[m.group(1)] = (p, status, cases, mapping)

    fns = {}  # name -> set(files)
    for p in tree.paths:
        if p.endswith(".rs") and (p.startswith("tests/") or p.startswith("src/")):
            for fm in TEST_FN.finditer(tree.read(p)):
                fns.setdefault(fm.group(1), set()).add(p)

    print(f"{'scenario':<9} {'status':<14} {'cases':>5} {'mapped':>6} {'missing':>7} {'orphan':>6}", file=out)
    for num in sorted(scenarios):
        p, status, cases, mapping = scenarios[num]
        enforced = status in ENFORCED
        live = {m[1] for m in mapping if m[3] == "live"}
        listed = {m[1] for m in mapping}
        missing = []
        for case, test, file, kind in mapping:
            if kind == "live":
                continue
            if test not in fns:
                missing.append(f"{test} (not found)")
            elif file and file not in fns[test]:
                missing.append(f"{test} (not in {file})")
            exp = "s" + case[1:].lower().replace("-", "_") + "_"
            if not test.startswith(exp):
                missing.append(f"{test} (name must start with {exp})")
        unmapped = [c for c in cases if c not in {m[0] for m in mapping}]
        missing += [f"{c} (no mapped test)" for c in unmapped]
        orphans = sorted(n for n in fns if n.startswith(f"s{num}_") and n not in listed)
        print(f"{num:<9} {status:<14} {len(cases):>5} {len(listed):>6} {len(missing):>7} {len(orphans):>6}", file=out)
        for m_ in missing:
            (f.fail if enforced else f.warn)(p, f"missing: {m_}")
        for o in orphans:
            (f.fail if enforced else f.warn)(p, f"orphan test: {o}")
        if live and not enforced:
            pass
    for name in sorted(fns):
        num = name[1:4]
        if num not in scenarios and num != "000":
            f.fail("tests", f"orphan test {name}: no scenarios/{num}-*.md")
    if f.items:
        print(f.render(), file=out)
    if not scenarios:
        print("no scenarios to cross-check (only the template)", file=out)
    print("scenario-coverage: " + ("FAIL" if f.failed() else "OK"), file=out)
    return 1 if f.failed() else 0


# --------------------------------------------------------------------------
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "scenario-coverage":
        ap = argparse.ArgumentParser(prog="check_docs.py scenario-coverage")
        ap.add_argument("--root", default=".")
        a = ap.parse_args(argv[1:])
        return scenario_coverage(a.root)
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--worktree", action="store_true", help="walk the directory instead of the Git index")
    ap.add_argument("--only", choices=("docs", "publish"))
    ap.add_argument("--env-file", help="KEY=VALUE file whose values are scanned for (never printed)")
    ap.add_argument("--denylist", default=os.environ.get("HOPAE_PUBLISH_DENYLIST"),
                    help="denylist file (default: $HOPAE_PUBLISH_DENYLIST)")
    ap.add_argument("--require-denylist", action="store_true")
    a = ap.parse_args(argv)
    tree = open_tree(a.root, a.worktree)
    f = Findings()
    n = 0
    if a.only in (None, "docs"):
        n = check_docs(tree, f)
    if a.only in (None, "publish"):
        check_publish(tree, f, a.denylist, a.env_file and os.path.expanduser(a.env_file),
                      a.require_denylist)
    src = "Git index" if tree.use_git else "working tree"
    print(f"check-docs: {len(tree.paths)} files in {src}, {n} markdown files checked")
    if f.items:
        print(f.render())
    print("check-docs: " + ("FAIL" if f.failed() else "OK"))
    return 1 if f.failed() else 0


if __name__ == "__main__":
    sys.exit(main())
