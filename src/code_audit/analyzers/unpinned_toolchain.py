"""Unpinned toolchain / floor-only CI-dep detector (v2 — section-based).

Flags a dependency with a **floor-only** version spec (``pkg>=X`` with no
ceiling) when it sits in a **dev / lint / test / ci** extras group (or a
``requirements-dev*.txt``). The gate is **structural position**, not a
hardcoded tool-name list.

**Why section-based (v2), not a name whitelist (v1):** a hardcoded
``{ruff, mypy, ...}`` set is itself a stale-prone fixed reference — any tool
not on it is invisible (Family III false-negative blind spot). Keying off
section position cannot go blind on a tool nobody enumerated. The known-tool
list is demoted to a **confidence booster**: recognised CI tools →
MEDIUM / 0.9; unlisted dev-section tools → LOW / 0.6.

**False-positive guards:** pinned (``==``), ceilinged (``>=24,<25``),
compatible-release (``~=``), commented lines, and runtime-section deps
(``api``, ``treesitter``, …) are not flagged.

Dogfood (this repo's ``pyproject.toml``):
  ``ruff>=0.4.0`` in ``dev`` → MEDIUM (known); ``pytest>=7.0`` etc. → LOW;
  ``api = [fastapi>=…,<…]`` → not flagged (runtime section + ceilinged).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "UNPINNED_TOOLCHAIN_001"

# Structural gate: optional-dependency / dependency-group names that mean
# "CI / dev toolchain" regardless of which tool sits inside.
_DEV_SECTION_NAMES = frozenset(
    {
        "dev",
        "lint",
        "linters",
        "test",
        "tests",
        "testing",
        "ci",
        "type",
        "types",
        "typing",
        "typecheck",
        "typechecking",
        "quality",
        "format",
        "formatting",
        "style",
        "check",
        "checks",
    }
)

# Confidence booster only — NOT the gate. Known reddening / CI-surface tools.
_KNOWN_CI_TOOLS = frozenset(
    {
        "ruff",
        "mypy",
        "black",
        "flake8",
        "pylint",
        "isort",
        "pyright",
        "basedpyright",
        "bandit",
        "vulture",
        "ssort",
        "autopep8",
        "yapf",
        "pyflakes",
        "pycodestyle",
        "pydocstyle",
        "mccabe",
        "radon",
        "xenon",
        "prospector",
        "semgrep",
        "pyre-check",
        "pytype",
        "blacken-docs",
        "docformatter",
        "coverage",
        "pytest-cov",
        "tox",
        "nox",
        "pre-commit",
    }
)

# PEP 508 / PEP 440 requirement line (name + optional extras + specifier).
_RE_REQ = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\s*\[[^\]]*\])?          # extras
    \s*
    (?P<spec>.*?)               # version specifier (may be empty)
    \s*$
    """,
    re.VERBOSE,
)

# Specifier tokens that bound the upper end (or fully pin).
_RE_CEILING = re.compile(r"(<=|<|==|===|~=)")
_RE_FLOOR = re.compile(r"(>=|>)")

# TOML section headers we care about.
_RE_OPT_DEPS_HEADER = re.compile(r"^\[project\.optional-dependencies\]\s*$")
_RE_DEP_GROUPS_HEADER = re.compile(r"^\[dependency-groups\]\s*$")
_RE_ANY_HEADER = re.compile(r"^\[[^\]]+\]\s*$")
# `dev = [` or `dev = ["a", "b"]`
_RE_ARRAY_KEY = re.compile(r'^([A-Za-z0-9_-]+)\s*=\s*\[(.*)$')
# A quoted string item, possibly with trailing comma.
_RE_QUOTED_ITEM = re.compile(r'''^\s*["']([^"']+)["']\s*,?\s*$''')
# Inline items after `[` on the same line: `"a", "b"]`
_RE_INLINE_QUOTED = re.compile(r'''["']([^"']+)["']''')

_REQ_DEV_GLOB_PREFIXES = ("requirements-dev", "requirements_dev")


@dataclass(frozen=True, slots=True)
class _Hit:
    name: str
    spec: str
    raw: str
    section: str
    line: int
    source: str  # relative path


class UnpinnedToolchainAnalyzer:
    """Detect floor-only version pins in dev/CI dependency sections."""

    id: str = "unpinned_toolchain"
    version: str = "2.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # Declaration surfaces only — ignore the discovered .py file list.
        findings: list[Finding] = []
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            findings.extend(self._scan_pyproject(pyproject, root))
        for req in sorted(root.iterdir()) if root.is_dir() else []:
            if not req.is_file():
                continue
            if _is_requirements_dev(req.name):
                findings.extend(self._scan_requirements(req, root))
        return findings

    # ── pyproject.toml ──────────────────────────────────────────────

    def _scan_pyproject(self, path: Path, root: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        hits = _parse_toml_dev_deps(text)
        rel = _rel(path, root)
        return [_to_finding(h, rel) for h in hits if _is_floor_only(h.spec)]

    # ── requirements-dev*.txt ───────────────────────────────────────

    def _scan_requirements(self, path: Path, root: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        rel = _rel(path, root)
        hits: list[_Hit] = []
        for i, raw_line in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw_line).strip()
            if not line or line.startswith("-"):  # -r / -e / flags
                continue
            parsed = _parse_requirement(line)
            if parsed is None:
                continue
            name, spec = parsed
            hits.append(
                _Hit(
                    name=name,
                    spec=spec,
                    raw=line,
                    section="requirements-dev",
                    line=i,
                    source=rel,
                )
            )
        return [_to_finding(h, rel) for h in hits if _is_floor_only(h.spec)]


# ── finding construction ────────────────────────────────────────────


def _to_finding(hit: _Hit, rel: str) -> Finding:
    # PEP 503 normalization — list is a confidence booster, not the gate.
    known = _normalize_name(hit.name) in {_normalize_name(n) for n in _KNOWN_CI_TOOLS}

    if known:
        severity = Severity.MEDIUM
        confidence = 0.9
    else:
        severity = Severity.LOW
        confidence = 0.6

    snippet = hit.raw.strip()
    message = (
        f"'{hit.name}{hit.spec}' in [{hit.section}] is floor-only (lower bound, "
        f"no ceiling) — CI can silently pull a newer major/minor and redden or "
        f"drift without a lock. Pin (==) or ceiling (>=X,<Y) toolchain deps in "
        f"dev/lint/test/ci sections so the CI toolchain cannot float unbound."
    )
    fp = make_fingerprint(_RULE_ID, rel, f"{hit.section}:{hit.name}", snippet)
    return Finding(
        finding_id=fp,
        type=AnalyzerType.UNPINNED_TOOLCHAIN,
        severity=severity,
        confidence=confidence,
        message=message,
        location=Location(path=rel, line_start=hit.line, line_end=hit.line),
        fingerprint=fp,
        snippet=snippet,
        metadata={
            "rule_id": _RULE_ID,
            "package": hit.name,
            "spec": hit.spec,
            "section": hit.section,
            "known_ci_tool": known,
            "detection_strategy": "section",
        },
    )


# ── parsers ─────────────────────────────────────────────────────────


def _parse_toml_dev_deps(text: str) -> list[_Hit]:
    """Line-aware scan of optional-dependencies / dependency-groups."""
    hits: list[_Hit] = []
    lines = text.splitlines()
    in_target_table = False  # [project.optional-dependencies] or [dependency-groups]
    current_section: str | None = None
    in_array = False

    for i, raw in enumerate(lines, start=1):
        line = _strip_comment(raw).rstrip()
        stripped = line.strip()

        if _RE_OPT_DEPS_HEADER.match(stripped) or _RE_DEP_GROUPS_HEADER.match(stripped):
            in_target_table = True
            current_section = None
            in_array = False
            continue

        if _RE_ANY_HEADER.match(stripped):
            in_target_table = False
            current_section = None
            in_array = False
            continue

        if not in_target_table:
            continue

        if not in_array:
            m = _RE_ARRAY_KEY.match(stripped)
            if not m:
                continue
            key, rest = m.group(1), m.group(2)
            current_section = key
            if current_section not in _DEV_SECTION_NAMES:
                # Still need to track whether this array is open so we don't
                # mis-attribute later keys — but we skip collecting items.
                in_array = "]" not in rest
                # If the array closes on this line and section is non-dev, ignore.
                if "]" in rest:
                    current_section = None
                    in_array = False
                continue

            # Dev section — collect inline items on this line, if any.
            if rest.strip() and rest.strip() != "]":
                for item in _RE_INLINE_QUOTED.findall(rest):
                    parsed = _parse_requirement(item)
                    if parsed is None:
                        continue
                    name, spec = parsed
                    hits.append(
                        _Hit(
                            name=name,
                            spec=spec,
                            raw=item,
                            section=current_section,
                            line=i,
                            source="pyproject.toml",
                        )
                    )
            if "]" in rest:
                current_section = None
                in_array = False
            else:
                in_array = True
            continue

        # Inside an array body.
        if stripped == "]" or stripped.startswith("]"):
            in_array = False
            current_section = None
            continue

        if current_section is None or current_section not in _DEV_SECTION_NAMES:
            continue

        m_item = _RE_QUOTED_ITEM.match(stripped)
        if not m_item:
            # Also accept inline multi-item remnants.
            for item in _RE_INLINE_QUOTED.findall(stripped):
                parsed = _parse_requirement(item)
                if parsed is None:
                    continue
                name, spec = parsed
                hits.append(
                    _Hit(
                        name=name,
                        spec=spec,
                        raw=item,
                        section=current_section,
                        line=i,
                        source="pyproject.toml",
                    )
                )
            if "]" in stripped:
                in_array = False
                current_section = None
            continue

        item = m_item.group(1)
        parsed = _parse_requirement(item)
        if parsed is not None:
            name, spec = parsed
            hits.append(
                _Hit(
                    name=name,
                    spec=spec,
                    raw=item,
                    section=current_section,
                    line=i,
                    source="pyproject.toml",
                )
            )
        if stripped.endswith("]") or "]," in stripped.replace(" ", ""):
            # rare: `"foo"]` on same line
            if stripped.endswith("]"):
                in_array = False
                current_section = None

    return hits


def _parse_requirement(raw: str) -> tuple[str, str] | None:
    s = raw.strip()
    if not s:
        return None
    m = _RE_REQ.match(s)
    if not m:
        return None
    name = m.group("name")
    spec = (m.group("spec") or "").strip()
    # Drop environment markers (``pkg>=1 ; python_version>="3.11"``).
    if ";" in spec:
        spec = spec.split(";", 1)[0].strip()
    return name, spec


def _is_floor_only(spec: str) -> bool:
    """True when the specifier has a lower bound and no upper/pin/compatible bound."""
    if not spec:
        return False  # bare name — out of scope for floor-only (v2)
    # Normalize commas/spaces for token search.
    if _RE_CEILING.search(spec):
        return False
    return _RE_FLOOR.search(spec) is not None


def _strip_comment(line: str) -> str:
    """Strip a ``#`` comment not inside a quoted string."""
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


def _is_requirements_dev(name: str) -> bool:
    lower = name.lower()
    if not (lower.endswith(".txt") or lower.endswith(".in")):
        return False
    stem = lower.rsplit(".", 1)[0]
    return any(stem == p or stem.startswith(p + "-") or stem.startswith(p + "_") for p in _REQ_DEV_GLOB_PREFIXES)


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
