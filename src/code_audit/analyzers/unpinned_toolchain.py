"""Unpinned toolchain analyzer (section-based) — detects dev/CI-tool dependencies
declared with a version floor but no ceiling, which can redden a green build with
no commit.

Family II (implicit context) at the build layer: a build's result depends on the
resolved version of a linter/type-checker, an unrecorded moving reference. A
floor-only spec lets CI resolve to newest-at-install, so a new tool release can
fail the build with no code change.

Strategy — section-based, NOT a name whitelist. A hardcoded tool set is itself a
stale-prone fixed reference: any tool not on it is invisible (a false negative,
the blind-spot class this suite catches). Instead we key off structural position
— a dependency in a dev/lint/test/ci extras group (or a requirements-dev file) IS
toolchain by definition, whatever its name. The known-tool list only boosts
confidence/severity. Runtime dep sections are not flagged (separate policy).

Supported declaration surfaces (v2.1):
  - ``pyproject.toml`` tables ``[project.optional-dependencies]`` and
    ``[dependency-groups]``
  - ``requirements-dev*.txt`` / ``requirements_*dev*.in`` (whole-file policy:
    every floor-only line is treated as toolchain)

``setup.cfg`` is intentionally NOT scanned — INI extras_require is a different
grammar; claiming TOML-style support there was a false coverage claim.
"""

from __future__ import annotations

import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Token-matched section names (split on [-_.]). Exact token equality — not
# substring containment — so "lifestyle" / "checksum" / "pricing" do not match.
_TOOLCHAIN_SECTION_TOKENS = frozenset(
    {
        "dev",
        "lint",
        "linters",
        "test",
        "tests",
        "testing",
        "ci",
        "typecheck",
        "typechecking",
        "typing",
        "types",
        "quality",
        "check",
        "checks",
        "style",
        "format",
        "formatting",
    }
)

_KNOWN_CI_TOOLS = frozenset(
    {
        "ruff",
        "mypy",
        "black",
        "flake8",
        "pylint",
        "isort",
        "pyright",
        "pyflakes",
        "pycodestyle",
        "bandit",
        "pyupgrade",
        "autoflake",
        "yapf",
        "pydocstyle",
        "vulture",
        "ssort",
        "docformatter",
        "flake8-bugbear",
    }
)

_HAS_FLOOR = re.compile(r"(>=|>)\s*\d")
_HAS_CEILING = re.compile(r"(<=|<|==|~=|===)\s*\d")
_DEP_SPEC = re.compile(
    r"""["']?
        ([A-Za-z0-9][A-Za-z0-9._-]*)
        \s*(?:\[[^\]]*\])?
        \s*([<>=!~][^"'#\n\]]*)
    """,
    re.VERBOSE,
)
_EXTRAS_OPEN = re.compile(r"""^\s*["']?([A-Za-z0-9._-]+)["']?\s*=\s*\[""")
_OPTDEP_TABLE = re.compile(
    r"^\s*\[(?:project\.optional-dependencies|dependency-groups)\]"
)


def _tool(raw: str) -> str:
    return raw.lower().replace("_", "-").strip()


def _version_spec_only(spec: str) -> str:
    """Drop PEP 508 environment markers (``; python_version < "3.13"``)."""
    return spec.split(";", 1)[0].strip().rstrip(",").strip()


def _is_floor_only(spec: str) -> bool:
    version_part = _version_spec_only(spec)
    if not version_part:
        return False
    return bool(_HAS_FLOOR.search(version_part)) and not _HAS_CEILING.search(
        version_part
    )


def _section_is_toolchain(name: str) -> bool:
    tokens = {t for t in re.split(r"[-_.]+", name.lower()) if t}
    return bool(tokens & _TOOLCHAIN_SECTION_TOKENS)


def _strip_comment(line: str) -> str:
    """Strip a ``#`` comment that is not inside a quoted string."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:idx]
    return line


class UnpinnedToolchainAnalyzer:
    """Flags floor-only version specs on dependencies located in a dev/CI section."""

    id: str = "unpinned_toolchain"
    version: str = "2.1.0"

    _REQ_DEV = re.compile(
        r"requirements[-_.].*(dev|lint|test|ci).*\.(txt|in)$", re.IGNORECASE
    )

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        # Always include declaration surfaces under root even if the runner only
        # passed .py files — matches other config-surface Tier-1 detectors.
        candidates = list(files)
        pyproject = root / "pyproject.toml"
        if pyproject.is_file() and pyproject not in candidates:
            candidates.append(pyproject)
        if root.is_dir():
            for p in sorted(root.iterdir()):
                if p.is_file() and self._REQ_DEV.search(p.name) and p not in candidates:
                    candidates.append(p)

        seen: set[Path] = set()
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)

            name = path.name
            # setup.cfg / other formats: skip — not a supported grammar in v2.1.
            if name == "setup.cfg":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = (
                    str(path.relative_to(root)) if path.is_absolute() else str(path)
                ).replace("\\", "/")
            if name == "pyproject.toml":
                findings.extend(self._scan_toml_like(text, rel))
            elif self._REQ_DEV.search(name):
                findings.extend(
                    self._scan_requirements(text, rel, "<dev-requirements-file>")
                )
        return findings

    def _scan_toml_like(self, text: str, rel: str) -> list[Finding]:
        out: list[Finding] = []
        in_optdep_table = False
        current_section: str | None = None
        in_array = False
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw)
            stripped = line.strip()
            if stripped.startswith("["):
                in_optdep_table = bool(_OPTDEP_TABLE.match(stripped))
                current_section = None
                in_array = False
                continue
            if in_array and current_section is not None:
                if _section_is_toolchain(current_section):
                    out.extend(self._flag_line(line, lineno, rel, current_section))
                if stripped.endswith("]"):
                    in_array = False
                    current_section = None
                continue
            m_open = _EXTRAS_OPEN.match(line)
            if m_open and in_optdep_table:
                grp = m_open.group(1)
                current_section = grp
                in_array = not stripped.rstrip().endswith("]")
                # Always scan the opener line — multiline inline arrays put the
                # first dep on this line before the array continues.
                if _section_is_toolchain(grp):
                    out.extend(self._flag_line(line, lineno, rel, grp))
                if not in_array:
                    current_section = None
                continue
        return out

    def _scan_requirements(self, text: str, rel: str, section: str) -> list[Finding]:
        out: list[Finding] = []
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw)
            if line.strip():
                out.extend(self._flag_line(line, lineno, rel, section))
        return out

    def _flag_line(
        self, line: str, lineno: int, rel: str, section: str
    ) -> list[Finding]:
        out: list[Finding] = []
        for m in _DEP_SPEC.finditer(line):
            tool = _tool(m.group(1))
            raw_spec = (m.group(2) or "").strip()
            spec = _version_spec_only(raw_spec)
            if not _is_floor_only(spec):
                continue
            known = tool in _KNOWN_CI_TOOLS
            out.append(
                self._finding(
                    rel, lineno, tool, spec, line.strip()[:80], section, known
                )
            )
        return out

    def _finding(self, rel, line, tool, spec, snippet, section, known):
        rule = "unpinned_toolchain.floor_only"
        fingerprint = make_fingerprint(rule, rel, tool, snippet)
        severity = Severity.MEDIUM if known else Severity.LOW
        confidence = 0.9 if known else 0.6
        note = (
            f"{tool!r} is a known CI-reddening tool; a new release can add rules "
            f"that fail the build."
            if known
            else (
                f"{tool!r} sits in the '{section}' toolchain group; an unbounded "
                f"floor lets its version drift at install time."
            )
        )
        return Finding(
            finding_id=fingerprint,
            type=AnalyzerType.UNPINNED_TOOLCHAIN,
            severity=severity,
            confidence=confidence,
            message=(
                f"Toolchain dependency {tool}{spec} (in '{section}') has a floor "
                f"but no ceiling. {note} CI resolves to newest-at-install, so the "
                f"build can redden with no commit. Pin it ({tool}==<version>) or "
                f"add an advisory preview job."
            ),
            location=Location(path=rel, line_start=line, line_end=line),
            fingerprint=fingerprint,
            snippet=snippet[:80],
            metadata={
                "tool": tool,
                "spec": spec,
                "section": section,
                "known_ci_tool": known,
                "remedy": "pin_or_advisory",
            },
        )
