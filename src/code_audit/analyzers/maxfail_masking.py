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
_WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

# ``--maxfail`` / ``--maxfail=N`` / ``--maxfail N`` — but NOT ``--maxfail=0``
# (0 means "no limit" = not fail-fast).
_RE_MAXFAIL = re.compile(r"--maxfail(?:[=\s]+(\d+))?")
_RE_EXITFIRST = re.compile(r"--exitfirst\b")
# ini ``maxfail = N`` option (pytest.ini / setup.cfg [tool:pytest]).
_RE_INI_MAXFAIL = re.compile(r"^\s*maxfail\s*=\s*(\d+)", re.MULTILINE)
# ``-x`` only when it's clearly a pytest flag on a command / addopts line.
_RE_PYTEST_X = re.compile(r"(?:pytest|addopts)\b[^\n]*?(?<!\S)-x(?!\S)")


class MaxfailMaskingAnalyzer:
    """Detect fail-fast test/CI config that hides the true failure set."""

    id: str = "maxfail_masking"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # This analyzer inspects config surfaces, not the discovered .py files.
        findings: list[Finding] = []
        for name in _ROOT_CONFIGS:
            findings.extend(self._scan_config(root / name, root))
        for pattern in _WORKFLOW_GLOBS:
            for wf in sorted(root.glob(pattern)):
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

        flags = _detect_fail_fast(text)
        if not flags:
            return []

        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.name

        line = flags[0][1]
        src_lines = text.splitlines()
        snippet = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
        flag_names = sorted({f[0] for f in flags})

        message = (
            f"'{rel}' runs pytest fail-fast ({', '.join(flag_names)}) — CI stops "
            f"at the first failure, so N independent failures are reported as one "
            f"and a stack of bugs looks like a single sequential surprise. "
            f"Fix: keep fail-fast for speed if you want, but add a collect-all pass "
            f"(pytest with no --maxfail/-x/--exitfirst) that enumerates the full "
            f"failure set and groups by cause — diagnose the whole stack at once."
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
                    # v1 cannot confirm whether a companion collect-all run exists;
                    # the v2 pass looks for one and downgrades/clears if present.
                    "collect_all_escape_confirmed": False,
                    "context_confirmed": False,
                },
            )
        ]


# ── detection ───────────────────────────────────────────────────────


def _detect_fail_fast(text: str) -> list[tuple[str, int]]:
    """Return (flag_name, 1-based line) for each fail-fast flag found."""
    hits: list[tuple[str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0]  # ignore trailing comments

        for m in _RE_MAXFAIL.finditer(line):
            val = m.group(1)
            if val is None or int(val) != 0:   # --maxfail=0 = unlimited = fine
                hits.append(("--maxfail", i))

        if _RE_EXITFIRST.search(line):
            hits.append(("--exitfirst", i))

        m = _RE_INI_MAXFAIL.match(line)
        if m and int(m.group(1)) != 0:
            hits.append(("maxfail", i))

        if _RE_PYTEST_X.search(line):
            hits.append(("-x", i))

    return hits
