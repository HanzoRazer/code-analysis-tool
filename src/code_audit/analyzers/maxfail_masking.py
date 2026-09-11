"""Maxfail-masking / serialized-failure detector.

Flags test/CI configuration that runs **fail-fast** (``--maxfail``, ``-x``,
``--exitfirst``, or the ``maxfail`` ini option). Fail-fast stops at the *first*
failure and hides the true failure set — N simultaneous, independent failures get
reported as one. The meta-bug: a *stack* of failures looks like a single
sequential surprise, so you fix one, re-run, hit the next, and a one-pass
diagnosis becomes days of whack-a-mole. **Family IV (instrument under-reports by
truncation).**

Universal: any repo whose CI runs ``pytest -x`` / ``--maxfail=N`` sees only the
first red on a broken run and cannot tell "one bug" from "a stack of them."

**v1** scans the known test/CI config surfaces — ``pyproject.toml``,
``pytest.ini``, ``tox.ini``, ``setup.cfg``, and ``.github/workflows/*.yml`` — for
fail-fast flags.

**v2** enriches findings by looking for a *collect-all escape*: a companion
pytest invocation that does **not** inherit fail-fast (either no root fail-fast,
or an explicit override such as ``-o addopts=""`` / ``--maxfail=0``). When
confirmed, findings stay but downgrade (INFO) — fail-fast for speed is fine if
a full-suite pass also enumerates the stack.

Emits: keep fail-fast for CI speed if you like, but add a **collect-all pass**
that enumerates the full failure set and groups by cause — don't diagnose a stack
one layer at a time.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "MAXFAIL_MASKING_001"

# Config surfaces that can carry a pytest fail-fast setting, relative to root.
_ROOT_CONFIGS = ("pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg")
_WORKFLOW_DIR = ".github/workflows"
_WORKFLOW_EXTS = frozenset({".yml", ".yaml"})  # matched case-insensitively

# ``--maxfail`` / ``--maxfail=N`` / ``--maxfail N`` — but NOT ``--maxfail=0``
# (0 means "no limit" = not fail-fast).
_RE_MAXFAIL = re.compile(r"--maxfail(?:[=\s]+(\d+))?")
_RE_EXITFIRST = re.compile(r"--exitfirst\b")
# ini ``maxfail = N`` option (pytest.ini / setup.cfg [tool:pytest]).
_RE_INI_MAXFAIL = re.compile(r"^\s*maxfail\s*=\s*(\d+)")
# A short-flag cluster containing ``x`` — matches -x, -xvs, -vsx (combined short
# flags are how pytest -x is usually written). A single leading '-' only, so
# long flags (--maxfail, --exitfirst) are excluded by the lookbehind.
_RE_SHORT_X = re.compile(r"(?<![\w-])-[a-zA-Z]*x[a-zA-Z]*(?![\w-])")
# Shell command separators — the ``-x`` must belong to the pytest invocation,
# not a later chained command (e.g. ``pytest && ssh -x host``).
_RE_CMD_SPLIT = re.compile(r"&&|\|\||;|\|")
_RE_PYTEST = re.compile(r"\b(?:pytest|py\.test)\b")

# Explicit overrides that clear / neutralize inherited addopts fail-fast.
# ``-o addopts=`` / ``-o addopts=""`` / ``--override-ini=addopts=`` /
# ``--override-ini addopts=`` (with optional empty quotes).
_RE_ADDOPTS_OVERRIDE = re.compile(
    r"""(?:-o|--override-ini)\s*(?:=\s*)?
        addopts\s*=\s*(?:""|'')?
        (?=\s|$|[^\w=])
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Escape:
    confirmed: bool
    evidence: str  # relative path + optional note; empty when not confirmed


class MaxfailMaskingAnalyzer:
    """Detect fail-fast test/CI config that hides the true failure set."""

    id: str = "maxfail_masking"
    version: str = "2.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # This analyzer inspects config surfaces, not the discovered .py files.
        root_fail_fast = _root_has_fail_fast(root)
        escape = _find_collect_all_escape(root, root_fail_fast=root_fail_fast)

        findings: list[Finding] = []
        for name in _ROOT_CONFIGS:
            findings.extend(
                self._scan_config(root / name, root, escape=escape)
            )
        wf_dir = root / _WORKFLOW_DIR
        if wf_dir.is_dir():
            for wf in sorted(wf_dir.iterdir()):
                if wf.is_file() and wf.suffix.lower() in _WORKFLOW_EXTS:
                    findings.extend(self._scan_config(wf, root, escape=escape))
        return findings

    # ── per-config scan ─────────────────────────────────────────────

    def _scan_config(
        self, path: Path, root: Path, *, escape: _Escape
    ) -> list[Finding]:
        if not path.is_file():
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        hits = _detect_fail_fast(text)
        if not hits:
            return []

        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.name

        line = hits[0].line
        src_lines = text.splitlines()
        snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
        flag_names = sorted({h.flag for h in hits})
        # Smallest positive maxfail bound found (how aggressively it truncates —
        # =1 hides the most). None if only -x/--exitfirst were seen.
        maxfail_values = [h.value for h in hits if h.value is not None]
        maxfail_value = min(maxfail_values) if maxfail_values else None

        limit_note = (
            f" (stops after {maxfail_value} failure{'s' if maxfail_value != 1 else ''})"
            if maxfail_value is not None
            else ""
        )

        if escape.confirmed:
            severity = Severity.INFO
            confidence = 0.45
            message = (
                f"'{rel}' runs pytest fail-fast ({', '.join(flag_names)})"
                f"{limit_note} — a companion collect-all escape is confirmed "
                f"({escape.evidence}), so the full failure set can still be "
                f"enumerated. Keep fail-fast for speed; rely on the collect-all "
                f"pass to diagnose stacks."
            )
        else:
            severity = Severity.LOW
            confidence = 0.6
            message = (
                f"'{rel}' runs pytest fail-fast ({', '.join(flag_names)})"
                f"{limit_note} — CI stops at the first failure(s), so N "
                f"independent failures are reported as one and a stack of bugs "
                f"looks like a single sequential surprise. Fix: keep fail-fast "
                f"for speed if you want, but add a collect-all pass (pytest with "
                f"no --maxfail/-x/--exitfirst, and "
                f'`-o addopts=""` if addopts inherits fail-fast) that enumerates '
                f"the full failure set and groups by cause — diagnose the whole "
                f"stack at once."
            )

        fingerprint = make_fingerprint(_RULE_ID, rel, flag_names[0], snippet)
        return [
            Finding(
                finding_id=fingerprint,
                type=AnalyzerType.MAXFAIL_MASKING,
                severity=severity,
                confidence=confidence,
                message=message,
                location=Location(path=rel, line_start=line, line_end=line),
                fingerprint=fingerprint,
                snippet=snippet,
                metadata={
                    "rule_id": _RULE_ID,
                    "fail_fast_flags": flag_names,
                    "maxfail_value": maxfail_value,
                    "collect_all_escape_confirmed": escape.confirmed,
                    "collect_all_escape_evidence": escape.evidence,
                },
            )
        ]


# ── detection ───────────────────────────────────────────────────────


class _Hit:
    __slots__ = ("flag", "line", "value")

    def __init__(self, flag: str, line: int, value: int | None = None) -> None:
        self.flag = flag
        self.line = line
        self.value = value


def _detect_fail_fast(text: str) -> list[_Hit]:
    """Return a hit for each fail-fast flag found (flag name, 1-based line, and
    the numeric value for ``--maxfail``/``maxfail`` if present)."""
    hits: list[_Hit] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)

        for m in _RE_MAXFAIL.finditer(line):
            val = int(m.group(1)) if m.group(1) is not None else None
            if val != 0:  # --maxfail=0 = unlimited = not fail-fast
                hits.append(_Hit("--maxfail", i, val))

        if _RE_EXITFIRST.search(line):
            hits.append(_Hit("--exitfirst", i))

        m = _RE_INI_MAXFAIL.match(line)
        if m and int(m.group(1)) != 0:
            hits.append(_Hit("maxfail", i, int(m.group(1))))

        # ``-x`` must belong to a pytest invocation / addopts, not a later
        # chained command. Scan only pytest-context segments of the line, and
        # match combined short-flag clusters (-x, -xvs).
        for segment in _RE_CMD_SPLIT.split(line):
            if _is_pytest_context(segment) and _RE_SHORT_X.search(segment):
                hits.append(_Hit("-x", i))
                break

    return hits


def _root_has_fail_fast(root: Path) -> bool:
    """True when a root pytest config surface declares fail-fast (inherited by
    bare ``pytest`` invocations in CI)."""
    for name in _ROOT_CONFIGS:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _detect_fail_fast(text):
            return True
    return False


def _find_collect_all_escape(root: Path, *, root_fail_fast: bool) -> _Escape:
    """Look for a companion pytest invocation that enumerates the full suite.

    A workflow (or root config) line is a collect-all escape when it invokes
    pytest **without** fail-fast flags, and either:

    - root config has no fail-fast to inherit, or
    - the line explicitly clears/neutralizes inherited addopts
      (``-o addopts=""`` / ``--override-ini addopts=``) or sets ``--maxfail=0``.
    """
    wf_dir = root / _WORKFLOW_DIR
    candidates: list[Path] = []
    if wf_dir.is_dir():
        candidates.extend(
            sorted(
                p
                for p in wf_dir.iterdir()
                if p.is_file() and p.suffix.lower() in _WORKFLOW_EXTS
            )
        )

    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.name

        for i, raw in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw)
            if not _line_has_pytest_invocation(line):
                continue
            if _line_is_collect_all(line, root_fail_fast=root_fail_fast):
                return _Escape(True, f"{rel}:{i}")

    return _Escape(False, "")


def _line_has_pytest_invocation(line: str) -> bool:
    """True when a line segment looks like a pytest/py.test command."""
    for segment in _RE_CMD_SPLIT.split(line):
        if _RE_PYTEST.search(segment):
            return True
    return False


def _line_is_collect_all(line: str, *, root_fail_fast: bool) -> bool:
    """True when this pytest line is a full-suite (non-fail-fast) run."""
    # Any positive fail-fast flag on the line (-x / --exitfirst / --maxfail=N>0)
    # means this invocation is itself fail-fast — not a collect-all escape.
    # (--maxfail=0 is never recorded as a hit by _detect_fail_fast.)
    if _detect_fail_fast(line):
        return False

    has_maxfail_zero = any(
        m.group(1) is not None and int(m.group(1)) == 0
        for m in _RE_MAXFAIL.finditer(line)
    )
    if has_maxfail_zero or _RE_ADDOPTS_OVERRIDE.search(line):
        return True

    # Bare pytest with no fail-fast flags — only an escape if root does not
    # inject fail-fast via addopts/ini.
    return not root_fail_fast


def _strip_comment(raw: str) -> str:
    """Drop a trailing ``#`` comment, but not a ``#`` inside a quoted string."""
    in_s = in_d = False
    for idx, ch in enumerate(raw):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return raw[:idx]
    return raw


def _is_pytest_context(segment: str) -> bool:
    """A line-segment where a ``-x`` would be a pytest flag: a pytest invocation,
    an addopts assignment, or a bare-flag line (a multiline addopts value where
    each flag sits on its own line)."""
    if _RE_PYTEST.search(segment):
        return True
    if "addopts" in segment:
        return True
    # A bare-flag line = every whitespace token is a flag (``-x``, ``-x -q``).
    # This excludes YAML list items like ``- run: curl -x`` (the ``- run:`` dash
    # is a lone ``-`` / ``run:`` token, not a flag).
    tokens = segment.split()
    return bool(tokens) and all(t.startswith("-") and len(t) > 1 for t in tokens)
