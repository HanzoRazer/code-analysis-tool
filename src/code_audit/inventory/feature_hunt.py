"""Feature-flag detector — finds feature flag usage across a codebase.

Port of the luthiers-toolbox ``feature_hunt.py`` concept.  Searches source
files for common feature-flag patterns — environment variables, SDK calls,
constant-name conventions — and reports each as a finding so stale flags can
be tracked and eventually removed.

Maps to ``AnalyzerType.DEAD_CODE`` (stale feature flags are dead code).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── Default detection patterns ────────────────────────────────────────

# Each entry: (compiled regex, human-readable label)
_DEFAULT_RAW_PATTERNS: list[tuple[str, str]] = [
    # Python os.environ / os.getenv for feature flags
    (r"""os\.(?:environ\.get|getenv)\s*\(\s*['"]FEATURE_""", "env-feature-flag"),
    # Python constant-name convention
    (r"""\bFEATURE_[A-Z0-9_]+\b""", "feature-constant"),
    (r"""\bFF_[A-Z0-9_]+\b""", "ff-constant"),
    # Common SDK patterns
    (r"""\bfeature_flags?\.\w+""", "feature-flag-sdk"),
    (r"""\bflags?\.is_(?:enabled|active)\b""", "flag-is-enabled"),
    (r"""\blaunch_?darkly\b""", "launchdarkly"),
    (r"""\bfeature_toggle\b""", "feature-toggle"),
    (r"""\bis_feature_enabled\b""", "is-feature-enabled"),
    (r"""\bunleash\.\w+""", "unleash"),
    (r"""\bflipper\.\w+""", "flipper"),
]

# File extensions to scan
_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"}
)


@dataclass(frozen=True, slots=True)
class FeatureFlagHit:
    """One occurrence of a feature flag reference (for programmatic use)."""

    pattern_label: str
    path: str
    line: int
    text: str


class FeatureHuntAnalyzer:
    """Scan source files for feature-flag usage patterns.

    Conforms to the ``Analyzer`` protocol (``id``, ``version``, ``run()``).

    Parameters
    ----------
    extra_patterns:
        Additional ``(regex, label)`` pairs to search for beyond defaults.
    extensions:
        File extensions to scan.
    include_defaults:
        Whether to include the built-in patterns.  Set *False* if you only
        want ``extra_patterns``.
    """

    id: str = "feature_hunt"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        extra_patterns: Sequence[tuple[str, str]] | None = None,
        extensions: frozenset[str] | None = None,
        include_defaults: bool = True,
    ) -> None:
        raw: list[tuple[str, str]] = []
        if include_defaults:
            raw.extend(_DEFAULT_RAW_PATTERNS)
        if extra_patterns:
            raw.extend(extra_patterns)

        self._patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p, re.IGNORECASE), label) for p, label in raw
        ]
        self._extensions = extensions or _DEFAULT_EXTENSIONS

    # ── Analyzer protocol ────────────────────────────────────────────

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Return one :class:`Finding` per feature-flag usage site."""
        findings: list[Finding] = []

        for path in files:
            if path.suffix.lower() not in self._extensions:
                continue

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            rel = str(path.relative_to(root))

            for line_no, line_text in enumerate(lines, start=1):
                for compiled, label in self._patterns:
                    for m in compiled.finditer(line_text):
                        snippet = line_text.strip()
                        findings.append(
                            Finding(
                                finding_id="",
                                type=AnalyzerType.DEAD_CODE,
                                severity=Severity.INFO,
                                confidence=0.80,
                                message=(
                                    f"Feature flag reference ({label}): "
                                    f"'{m.group()}'"
                                ),
                                location=Location(
                                    path=rel,
                                    line_start=line_no,
                                    line_end=line_no,
                                ),
                                fingerprint=make_fingerprint(
                                    "INV-FEATURE-FLAG", rel, label, snippet,
                                ),
                                snippet=snippet,
                                metadata={
                                    "rule_id": "INV-FEATURE-FLAG",
                                    "pattern_label": label,
                                    "match": m.group(),
                                },
                            )
                        )

        # Assign stable IDs
        for i, f in enumerate(findings):
            object.__setattr__(
                f, "finding_id", f"fh_{f.fingerprint[7:15]}_{i:04d}"
            )
        return findings

    # ── Convenience API ──────────────────────────────────────────────

    def hunt(self, root: Path, files: list[Path]) -> list[FeatureFlagHit]:
        """Return lightweight :class:`FeatureFlagHit` objects (no Finding overhead)."""
        hits: list[FeatureFlagHit] = []

        for path in files:
            if path.suffix.lower() not in self._extensions:
                continue

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            rel = str(path.relative_to(root))

            for line_no, line_text in enumerate(lines, start=1):
                for compiled, label in self._patterns:
                    for m in compiled.finditer(line_text):
                        hits.append(
                            FeatureFlagHit(
                                pattern_label=label,
                                path=rel,
                                line=line_no,
                                text=line_text.strip(),
                            )
                        )

        return hits
