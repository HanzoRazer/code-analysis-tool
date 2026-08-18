"""Hollow-guarantee / un-failable CI guard detector.

Flags CI **verification** steps configured so they *cannot fail* — the step runs a
check (type-check, lint, tests, static analysis), reports whatever it finds, and the
job goes green anyway. The guard looks like it verifies something and structurally
cannot report a failure. **Family III (failure that mimics success)** — the CI-config
sibling of a test that only asserts ``is_file()`` or a bare ``except`` that swallows
everything: green means nothing on that lane, so a real regression (e.g. a
major-version dependency bump turning 400 type errors into 4,000) sails through green.

Distinct from ``maxfail_masking`` (Family IV): that flags fail-fast (``--maxfail``/
``-x``) where the check *can* fail but truncates to the first failure. Here the check
*cannot fail at all*.

Signatures detected (v1, high-confidence):
  1. ``continue-on-error: true`` on a step whose command is a verification tool
     (tsc/vue-tsc, eslint, pytest, mypy, ruff, jest/vitest, ``npm run lint|type-check|
     test``, ``go test``, ``cargo test|clippy`` …). A ``continue-on-error`` on a
     genuinely-optional step (upload/notify/deploy) is NOT flagged — the verification
     match is the discriminator.
  2. A verification command with its exit swallowed inline: ``... || true``,
     ``... || exit 0``, ``... ; true``.

Emits: make the guard able to fail. If the failures are known debt, ratchet them
(freeze a baseline count, fail on any increase) rather than suppressing the lane —
so the guard catches regressions while tolerating the existing debt.

Universal: any repo with a GitHub Actions verification step under
``continue-on-error: true`` (or ``|| true``) has a lane whose green is not a
guarantee.
"""
from __future__ import annotations

import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "HOLLOW_GUARANTEE_001"

_WORKFLOW_DIR = ".github/workflows"
_WORKFLOW_EXTS = frozenset({".yml", ".yaml"})  # matched case-insensitively

# Verification tools whose exit code is a real signal. Word-ish boundaries so
# "prettier" doesn't match inside another token. Case-insensitive.
_VERIFICATION = re.compile(
    r"""(?<![\w./-])(?:
        tsc | vue-tsc | eslint | stylelint | prettier\s+--check |
        pytest | py\.test | mypy | pyright | ruff | flake8 | pylint | bandit |
        jest | vitest | ava | mocha | karma |
        go\s+test | go\s+vet | cargo\s+test | cargo\s+clippy | clippy |
        rubocop | phpstan | psalm | phpunit | rspec |
        black\s+--check | isort\s+--check |
        npm\s+run\s+(?:lint|type-?check|typecheck|test|check) |
        yarn\s+(?:lint|type-?check|typecheck|test|check) |
        pnpm\s+(?:lint|type-?check|typecheck|test|check)
    )(?![\w-])""",
    re.IGNORECASE | re.VERBOSE,
)

# `continue-on-error: true` (YAML boolean, tolerant of quotes/case).
_CONTINUE_ON_ERROR_TRUE = re.compile(
    r"""^\s*continue-on-error\s*:\s*['"]?(?:true|yes|on)['"]?\s*(?:\#.*)?$""",
    re.IGNORECASE,
)

# A step list item under `steps:` — `- name:` / `- uses:` / `- run:` / `- id:`.
_STEP_MARKER = re.compile(r"^(\s*)-\s+\S")

# Inline exit-swallow appended to a command: `|| true`, `|| exit 0`, `; true`.
_SWALLOW = re.compile(r"(\|\|\s*(?:true|exit\s+0)\b|;\s*true\b)")


class _Step:
    __slots__ = ("start_line", "indent", "lines")

    def __init__(self, start_line: int, indent: int) -> None:
        self.start_line = start_line
        self.indent = indent
        self.lines: list[tuple[int, str]] = []  # (1-based lineno, raw line)

    def text(self) -> str:
        return "\n".join(l for _, l in self.lines)


def _iter_steps(text: str):
    """Yield _Step blocks. A step is a `- ...` list item and every deeper-indented
    line until the next list item at the same-or-shallower indent. Non-step content
    (job keys, top-level) is ignored — we only care about step bodies."""
    lines = text.splitlines()
    current: _Step | None = None
    for i, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            if current is not None:
                current.lines.append((i, raw))
            continue
        m = _STEP_MARKER.match(raw)
        indent = len(raw) - len(raw.lstrip())
        if m:
            # A new list item. Close the current step if this marker is at the
            # same-or-shallower indent (sibling/ancestor), else it's a nested list.
            if current is not None and indent <= current.indent:
                yield current
                current = None
            if current is None:
                current = _Step(i, indent)
            current.lines.append((i, raw))
        else:
            if current is not None and indent > current.indent:
                current.lines.append((i, raw))
            elif current is not None:
                # dedent below the step — the step block has ended.
                yield current
                current = None
    if current is not None:
        yield current


def _verification_command(step_text: str) -> str | None:
    """Return the matched verification tool if the step runs one, else None.
    Only `run:`/`uses:`/`name:` content is considered (not the whole step)."""
    m = _VERIFICATION.search(step_text)
    return m.group(0).strip() if m else None


def _line_of(step: _Step, pattern: re.Pattern) -> int:
    for lineno, raw in step.lines:
        if pattern.match(raw) if pattern is _CONTINUE_ON_ERROR_TRUE else pattern.search(raw):
            return lineno
    return step.start_line


class HollowGuaranteeAnalyzer:
    """Detect CI verification steps that structurally cannot fail (Family III)."""

    id: str = "hollow_guarantee"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        wf_dir = root / _WORKFLOW_DIR
        if not wf_dir.is_dir():
            return []
        findings: list[Finding] = []
        for wf in sorted(wf_dir.iterdir()):
            if wf.is_file() and wf.suffix.lower() in _WORKFLOW_EXTS:
                findings.extend(self._scan(wf, root))
        return findings

    def _scan(self, path: Path, root: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.name

        out: list[Finding] = []
        for step in _iter_steps(text):
            step_text = step.text()
            tool = _verification_command(step_text)
            if tool is None:
                continue

            has_coe = any(_CONTINUE_ON_ERROR_TRUE.match(l) for _, l in step.lines)
            swallow = _SWALLOW.search(step_text)

            if has_coe:
                line = _line_of(step, _CONTINUE_ON_ERROR_TRUE)
                out.append(self._finding(
                    rel, line, tool,
                    kind="continue-on-error: true",
                    snippet=self._snippet(step, line),
                ))
            elif swallow:
                line = _line_of(step, _SWALLOW)
                out.append(self._finding(
                    rel, line, tool,
                    kind=f"exit swallowed ({swallow.group(1).strip()})",
                    snippet=self._snippet(step, line),
                    confidence=0.6,
                ))
        return out

    @staticmethod
    def _snippet(step: _Step, line: int) -> str:
        for lineno, raw in step.lines:
            if lineno == line:
                return raw.strip()
        return ""

    def _finding(self, rel: str, line: int, tool: str, *, kind: str,
                 snippet: str, confidence: float = 0.7) -> Finding:
        fingerprint = make_fingerprint(_RULE_ID, rel, tool, snippet)
        message = (
            f"'{rel}' runs a verification step ({tool}) under {kind} — the check "
            f"reports errors but the lane goes green regardless, so it structurally "
            f"cannot fail (Family III: a guard that mimics success). A real "
            f"regression on this lane is invisible. Fix: make the guard able to "
            f"fail — if the failures are known debt, ratchet them (freeze a baseline "
            f"count and fail on any increase) rather than suppressing the lane."
        )
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.HOLLOW_GUARANTEE,
            severity=Severity.LOW,   # advisory v1: never block scan exit
            confidence=confidence,
            message=message,
            location=Location(path=rel, line_start=line, line_end=line),
            fingerprint=fingerprint,
            snippet=snippet,
            metadata={
                "rule_id": _RULE_ID,
                "verification_tool": tool,
                "guard_kind": kind,
                "family": "III (failure mimics success)",
            },
        )
