"""Legacy-usage gate — detects frontend references to legacy API endpoints.

Generalization of the luthiers-toolbox ``legacy_usage_gate.py``.
Scans source files (TypeScript, JavaScript, Vue, Python, etc.) for string
literals that match legacy route patterns.  Supports:

*  **Budget mode** — exit OK if the count is within a shrinking budget.
*  **Fail-on-any** — hard-fail on any match (default for CI gates).

Maps to ``AnalyzerType.DEAD_CODE`` (legacy usage impedes removal).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Default legacy route patterns (regexes matching path strings)
_DEFAULT_LEGACY_PATTERNS: list[dict[str, str]] = [
    {
        "pattern": r"/api/v1/",
        "replacement": "/api/v2/",
        "label": "v1-api",
    },
]

# File extensions to scan by default
_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".vue", ".py", ".svelte"}
)


class LegacyUsageAnalyzer:
    """Scans for string literals referencing legacy API routes.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).

    Parameters
    ----------
    legacy_routes:
        A list of dicts with ``pattern``, ``replacement``, and ``label`` keys.
        If *None* defaults are used.  Can also be the path to a JSON file
        containing a ``routes`` array.
    extensions:
        File extensions to scan.
    budget:
        Maximum number of matches before severity escalates to HIGH.
        *None* means no budget (all matches are MEDIUM).
    """

    id: str = "legacy_usage"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        legacy_routes: list[dict[str, str]] | Path | str | None = None,
        extensions: frozenset[str] | None = None,
        budget: int | None = None,
    ) -> None:
        self._routes = self._resolve_routes(legacy_routes)
        self._extensions = extensions or _DEFAULT_EXTENSIONS
        self._budget = budget
        # Pre-compile all route patterns
        self._compiled: list[tuple[re.Pattern[str], str, str]] = [
            (re.compile(r["pattern"]), r.get("replacement", ""), r.get("label", ""))
            for r in self._routes
        ]

    @staticmethod
    def _resolve_routes(
        routes: list[dict[str, str]] | Path | str | None,
    ) -> list[dict[str, str]]:
        if routes is None:
            return list(_DEFAULT_LEGACY_PATTERNS)
        if isinstance(routes, (str, Path)):
            p = Path(routes)
            data: Any = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get("routes", [])
            return data if isinstance(data, list) else []
        return list(routes)

    # ------------------------------------------------------------------

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            if path.suffix not in self._extensions:
                continue

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            rel = str(path.relative_to(root))

            for line_no, line_text in enumerate(lines, start=1):
                for compiled_pat, replacement, label in self._compiled:
                    for m in compiled_pat.finditer(line_text):
                        snippet = line_text.strip()
                        msg = (
                            f"Legacy route pattern '{label or compiled_pat.pattern}' "
                            f"found"
                        )
                        if replacement:
                            msg += f" — migrate to '{replacement}'"

                        findings.append(
                            Finding(
                                finding_id="",
                                type=AnalyzerType.DEAD_CODE,
                                severity=Severity.MEDIUM,
                                confidence=0.80,
                                message=msg,
                                location=Location(
                                    path=rel,
                                    line_start=line_no,
                                    line_end=line_no,
                                ),
                                fingerprint=make_fingerprint(
                                    "GOV-LEGACY-USAGE",
                                    rel,
                                    str(line_no),
                                    snippet,
                                ),
                                snippet=snippet,
                                metadata={
                                    "rule_id": "GOV-LEGACY-USAGE",
                                    "pattern": compiled_pat.pattern,
                                    "match": m.group(0),
                                    "label": label,
                                    **(
                                        {"replacement": replacement}
                                        if replacement
                                        else {}
                                    ),
                                },
                            )
                        )

        # Budget escalation: over budget → HIGH
        if self._budget is not None and len(findings) > self._budget:
            for f in findings:
                object.__setattr__(f, "severity", Severity.HIGH)

        # Assign IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"leg_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings
