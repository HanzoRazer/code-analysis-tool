"""SDK boundary violation scanner — detects frontend code bypassing the SDK layer.

Port of the luthiers-toolbox ``scan_frontend_api_usage.py`` concept.
Scans frontend files (TypeScript, JavaScript, Vue, Svelte) for direct API
call patterns that should go through an SDK or service layer.

Enforces the architecture:  **Frontend → SDK → API**

Direct ``fetch("/api/…")``, ``axios.get("/api/…")``, or bare URL-string
references to API paths in frontend code are flagged.

Maps to ``AnalyzerType.SECURITY`` (boundary violations are an architecture
concern).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── Default detection patterns ────────────────────────────────────────

_DEFAULT_API_PREFIXES: list[str] = [
    r"/api/",
]

# Common direct-call patterns in frontend code
_DIRECT_CALL_PATTERNS: list[tuple[str, str]] = [
    (r"""fetch\s*\(\s*[`'"]\s*{prefix}""", "fetch-direct"),
    (r"""axios\.\w+\s*\(\s*[`'"]\s*{prefix}""", "axios-direct"),
    (r"""http\.\w+\s*\(\s*[`'"]\s*{prefix}""", "http-direct"),
    (r"""\$http\.\w+\s*\(\s*[`'"]\s*{prefix}""", "angular-http-direct"),
    (r"""\.get\s*\(\s*[`'"]\s*{prefix}""", "get-direct"),
    (r"""\.post\s*\(\s*[`'"]\s*{prefix}""", "post-direct"),
    (r"""\.put\s*\(\s*[`'"]\s*{prefix}""", "put-direct"),
    (r"""\.delete\s*\(\s*[`'"]\s*{prefix}""", "delete-direct"),
    (r"""\.patch\s*\(\s*[`'"]\s*{prefix}""", "patch-direct"),
]

_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"}
)

# Directories to always skip (node_modules, dist, build, etc.)
_SKIP_DIRS: frozenset[str] = frozenset(
    {"node_modules", "dist", "build", ".next", ".nuxt", "__pycache__"}
)


class SdkBoundaryAnalyzer:
    """Detect frontend code making direct API calls instead of using the SDK.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).

    Parameters
    ----------
    api_prefixes:
        URL path prefixes that indicate an API call (e.g. ``["/api/"]``).
    allowed_files:
        Glob patterns for files that are *allowed* to make direct API calls
        (e.g. the SDK module itself).
    extensions:
        File extensions to scan.
    extra_patterns:
        Additional ``(regex_template, label)`` pairs.  ``{prefix}`` in the
        template is replaced with each API prefix.
    """

    id: str = "sdk_boundary"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        api_prefixes: list[str] | None = None,
        allowed_files: list[str] | None = None,
        extensions: frozenset[str] | None = None,
        extra_patterns: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        prefixes = api_prefixes or list(_DEFAULT_API_PREFIXES)
        self._allowed_globs = allowed_files or []
        self._extensions = extensions or _DEFAULT_EXTENSIONS

        # Build compiled patterns for every prefix × call-pattern combination
        raw_patterns: list[tuple[str, str]] = list(_DIRECT_CALL_PATTERNS)
        if extra_patterns:
            raw_patterns.extend(extra_patterns)

        self._patterns: list[tuple[re.Pattern[str], str]] = []
        for regex_template, label in raw_patterns:
            for prefix in prefixes:
                escaped = re.escape(prefix)
                regex = regex_template.replace("{prefix}", escaped)
                self._patterns.append((re.compile(regex, re.IGNORECASE), label))

    # ── Analyzer protocol ────────────────────────────────────────────

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Return one :class:`Finding` per direct API call."""
        findings: list[Finding] = []

        for path in files:
            if path.suffix.lower() not in self._extensions:
                continue

            # Skip paths in excluded directories
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                continue
            if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
                continue

            # Skip allowed files (e.g. the SDK itself)
            if self._is_allowed(path, root):
                continue

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for line_no, line_text in enumerate(lines, start=1):
                # Skip commented-out lines
                stripped = line_text.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for compiled, label in self._patterns:
                    for m in compiled.finditer(line_text):
                        snippet = line_text.strip()
                        findings.append(
                            Finding(
                                finding_id="",
                                type=AnalyzerType.SECURITY,
                                severity=Severity.MEDIUM,
                                confidence=0.90,
                                message=(
                                    f"Direct API call ({label}) bypasses SDK layer — "
                                    f"use the SDK client instead"
                                ),
                                location=Location(
                                    path=rel,
                                    line_start=line_no,
                                    line_end=line_no,
                                ),
                                fingerprint=make_fingerprint(
                                    "GOV-SDK-BOUNDARY", rel, label, snippet,
                                ),
                                snippet=snippet,
                                metadata={
                                    "rule_id": "GOV-SDK-BOUNDARY",
                                    "pattern_label": label,
                                    "match": m.group(),
                                },
                            )
                        )

        # Assign stable IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"sb_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings

    # ── helpers ───────────────────────────────────────────────────────

    def _is_allowed(self, path: Path, root: Path) -> bool:
        """Check if *path* is in the allow-list (e.g. SDK module itself)."""
        if not self._allowed_globs:
            return False
        rel = path.relative_to(root)
        return any(rel.match(g) for g in self._allowed_globs)
