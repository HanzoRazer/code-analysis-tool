"""Import-ban analyzer — enforces migration away from deprecated module paths.

Generalization of the luthiers-toolbox ``ban_experimental_ai_core_imports.py``.
Instead of hard-coding a single banned prefix, accepts a configurable list of
regex patterns.  Any ``import`` or ``from … import`` that matches a pattern
produces a finding.

Maps to ``AnalyzerType.SECURITY`` (banned imports are a supply-chain /
architecture-boundary concern).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_DEFAULT_PATTERNS: list[str] = [
    r"app\._experimental\.ai_core",
]


def _import_module_names(node: ast.AST) -> list[str]:
    """Extract the full dotted module name(s) from an import node."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        return [node.module] if node.module else []
    return []


class ImportBanAnalyzer:
    """Scans for imports matching forbidden patterns.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).
    """

    id: str = "import_ban"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        banned_patterns: list[str] | None = None,
        skip_shims: bool = True,
    ) -> None:
        raw = banned_patterns if banned_patterns is not None else _DEFAULT_PATTERNS
        self._patterns = [re.compile(p) for p in raw]
        self._skip_shims = skip_shims

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = str(path.relative_to(root))

            # Optionally skip shim files (files that re-export the banned module)
            if self._skip_shims and "_shim" in path.stem:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue

                for module_name in _import_module_names(node):
                    if not any(p.search(module_name) for p in self._patterns):
                        continue

                    end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
                    snippet = f"import {module_name}"
                    if isinstance(node, ast.ImportFrom):
                        names = ", ".join(a.name for a in node.names)
                        snippet = f"from {module_name} import {names}"

                    findings.append(
                        Finding(
                            finding_id="",
                            type=AnalyzerType.SECURITY,
                            severity=Severity.HIGH,
                            confidence=0.99,
                            message=(
                                f"Banned import '{module_name}' — "
                                f"migrate to the canonical path"
                            ),
                            location=Location(
                                path=rel,
                                line_start=node.lineno,
                                line_end=end_line,
                            ),
                            fingerprint=make_fingerprint(
                                "GOV-IMPORT-BAN", rel, module_name, snippet
                            ),
                            snippet=snippet,
                            metadata={
                                "rule_id": "GOV-IMPORT-BAN",
                                "banned_module": module_name,
                            },
                        )
                    )

        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"ib_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings
