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
fail-fast flags. It records in ``metadata`` whether a *collect-all escape* (a
companion run with no fail-fast flag, i.e. a full-suite pass that enumerates
everything) is **confirmed** — ``False`` in v1. A v2 pass enriches this by looking
for that companion job, and downgrades when one exists.

Emits: keep fail-fast for CI speed if you like, but add a **collect-all pass**
that enumerates the full failure set and groups by cause — don't diagnose a stack
one layer at a time.
"""
from __future__ import annotations

import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "MAXFAIL_MASKING_001"

# Config surfaces that can carry a pytest fail-fast setting, relative to root.
_ROOT_CONFIGS = ("pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg")
_WORKFLOW_DIR = ".github/workflows"
_WORKFLOW_EXTS = frozenset({".yml", ".yaml"})   # matched case-insensitively

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


class MaxfailMaskingAnalyzer:
    """Detect fail-fast test/CI config that hides the true failure set."""

    id: str = "maxfail_masking"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # This analyzer inspects config surfaces, not the discovered .py files.
        findings: list[Finding] = []
        for name in _ROOT_CONFIGS:
            findings.extend(self._scan_config(root / name, root))
        wf_dir = root / _WORKFLOW_DIR
        if wf_dir.is_dir():
            # Case-insensitive .yml/.yaml (GitHub only recognises lowercase, but
            # be robust on case-sensitive filesystems regardless).
            for wf in sorted(wf_dir.iterdir()):
                if wf.is_file() and wf.suffix.lower() in _WORKFLOW_EXTS:
                    findings.extend(self._scan_config(wf, root))
        return findings

    # ── per-config scan ─────────────────────────────────────────────

    def _scan_config(self, path: Path, root: Path) -> list[Finding]:
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
        message = (
            f"'{rel}' runs pytest fail-fast ({', '.join(flag_names)}){limit_note} — "
            f"CI stops at the first failure(s), so N independent failures are "
            f"reported as one and a stack of bugs looks like a single sequential "
            f"surprise. Fix: keep fail-fast for speed if you want, but add a "
            f"collect-all pass (pytest with no --maxfail/-x/--exitfirst) that "
            f"enumerates the full failure set and groups by cause — diagnose the "
            f"whole stack at once."
        )
        fingerprint = make_fingerprint(_RULE_ID, rel, flag_names[0], snippet)
        return [
            Finding(
                finding_id=fingerprint,
                type=AnalyzerType.MAXFAIL_MASKING,
                severity=Severity.LOW,
                confidence=0.6,
                message=message,
                location=Location(path=rel, line_start=line, line_end=line),
                fingerprint=fingerprint,
                snippet=snippet,
                metadata={
                    "rule_id": _RULE_ID,
                    "fail_fast_flags": flag_names,
                    "maxfail_value": maxfail_value,
                    # v1 cannot confirm whether a companion collect-all run exists;
                    # the v2 pass looks for one and downgrades/clears if present.
                    "collect_all_escape_confirmed": False,
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
            if val != 0:   # --maxfail=0 = unlimited = not fail-fast
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
