"""Safety fence analyzer — enforces safety-critical code contracts.

Ported from the luthiers-toolbox ``fence_checker_v2.py`` CI tool.

Two checks:

1. **Bare-except gate** — ``except:`` clauses without a specific type
   are forbidden.  (These hide bugs and can swallow ``KeyboardInterrupt``.)

2. **Safety-decorator gate** — functions whose names match configurable
   patterns (e.g. ``generate_gcode``, ``calculate_feeds``) **must** be
   decorated with ``@safety_critical``.  Functions with ``_hash`` / ``_stub``
   suffixes and Protocol classes are excluded.

Both checks produce ``Finding`` objects with ``AnalyzerType.SAFETY``
and feed into the standard pipeline (confidence scoring, signals, etc.).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── defaults ─────────────────────────────────────────────────────────

# Function-name patterns that require @safety_critical
_DEFAULT_SAFETY_PATTERNS: list[str] = [
    r"generate_gcode",
    r"calculate_feeds",
    r"compute_feasibility",
    r"validate_toolpath",
]

# Function-name suffixes to exclude from the decorator check
_DEFAULT_EXCLUDE_SUFFIXES: tuple[str, ...] = ("_hash", "_stub")

# Decorator name to look for
_SAFETY_DECORATOR = "safety_critical"


def _has_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Return True if *node* has a decorator whose base name is *name*."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == name:
            return True
        if isinstance(dec, ast.Attribute) and dec.attr == name:
            return True
        # @module.safety_critical(...)
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id == name:
                return True
            if isinstance(func, ast.Attribute) and func.attr == name:
                return True
    return False


def _is_protocol_class(node: ast.ClassDef) -> bool:
    """Return True if *node* inherits from ``Protocol``."""
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id == "Protocol":
            return True
        if isinstance(base, ast.Attribute) and base.attr == "Protocol":
            return True
    return False


class SafetyFenceAnalyzer:
    """Enforces safety fences: bare-except blocking + decorator enforcement.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).
    """

    id: str = "safety_fence"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        safety_patterns: list[str] | None = None,
        exclude_suffixes: tuple[str, ...] = _DEFAULT_EXCLUDE_SUFFIXES,
        decorator_name: str = _SAFETY_DECORATOR,
        check_bare_except: bool = True,
    ) -> None:
        raw = safety_patterns if safety_patterns is not None else _DEFAULT_SAFETY_PATTERNS
        self._patterns = [re.compile(p) for p in raw]
        self._exclude_suffixes = exclude_suffixes
        self._decorator_name = decorator_name
        self._check_bare_except = check_bare_except

    # ── Analyzer protocol ────────────────────────────────────────────

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = path.relative_to(root).as_posix()

            if self._check_bare_except:
                findings.extend(self._check_bare_excepts(tree, rel))

            findings.extend(self._check_safety_decorators(tree, rel))

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"sf_{f.fingerprint[7:15]}_{i:04d}"
            )

        return findings

    # ── internal checks ──────────────────────────────────────────────

    def _check_bare_excepts(self, tree: ast.Module, rel: str) -> list[Finding]:
        """Flag every bare ``except:`` clause."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is not None:
                continue  # not bare

            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
            snippet = "except:\n    ..."

            findings.append(
                Finding(
                    finding_id="",
                    type=AnalyzerType.SAFETY,
                    severity=Severity.HIGH,
                    confidence=0.99,
                    message="Bare except hides bugs and can swallow KeyboardInterrupt",
                    location=Location(path=rel, line_start=node.lineno, line_end=end_line),
                    fingerprint=make_fingerprint(
                        "FENCE-BARE-EXCEPT", rel, "<handler>", snippet
                    ),
                    snippet=snippet,
                    metadata={"rule_id": "FENCE-BARE-EXCEPT", "fence_type": "safety"},
                )
            )
        return findings

    def _check_safety_decorators(
        self, tree: ast.Module, rel: str
    ) -> list[Finding]:
        """Flag safety-critical functions missing @safety_critical."""
        findings: list[Finding] = []

        # Collect Protocol class bodies so we can skip them
        protocol_bodies: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and _is_protocol_class(node):
                for child in ast.walk(node):
                    protocol_bodies.add(id(child))

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Skip Protocol methods
            if id(node) in protocol_bodies:
                continue

            # Skip excluded suffixes
            if any(node.name.endswith(s) for s in self._exclude_suffixes):
                continue

            # Check if name matches any safety pattern
            if not any(p.search(node.name) for p in self._patterns):
                continue

            # Must have the decorator
            if _has_decorator(node, self._decorator_name):
                continue

            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
            snippet = f"def {node.name}(...)  # missing @{self._decorator_name}"

            findings.append(
                Finding(
                    finding_id="",
                    type=AnalyzerType.SAFETY,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    message=(
                        f"Safety-critical function '{node.name}' is missing "
                        f"@{self._decorator_name} decorator"
                    ),
                    location=Location(path=rel, line_start=node.lineno, line_end=end_line),
                    fingerprint=make_fingerprint(
                        "FENCE-SAFETY-DECORATOR", rel, node.name, snippet
                    ),
                    snippet=snippet,
                    metadata={
                        "rule_id": "FENCE-SAFETY-DECORATOR",
                        "fence_type": "safety",
                        "function_name": node.name,
                        "expected_decorator": self._decorator_name,
                    },
                )
            )

        return findings
