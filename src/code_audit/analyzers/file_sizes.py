"""File sizes analyzer — detects files that have grown too large."""

from __future__ import annotations

from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Thresholds (configurable via config layer later)
_THRESHOLD = 500   # lines
_HIGH = 800        # severe threshold


class FileSizesAnalyzer:
    """Finds Python files exceeding line count threshold.

    Large files are harder to maintain, test, and review.
    They often indicate a need for splitting or refactoring.
    """

    id: str = "file_sizes"
    version: str = "1.0.0"

    def __init__(self, threshold: int = _THRESHOLD, high_threshold: int = _HIGH):
        self.threshold = threshold
        self.high_threshold = high_threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            if path.suffix != ".py":
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                line_count = len(lines)
            except (OSError, IOError):
                continue

            if line_count <= self.threshold:
                continue

            rel = str(path.relative_to(root))
            over_by = line_count - self.threshold
            severity = Severity.HIGH if line_count >= self.high_threshold else Severity.MEDIUM
            rule_id = "FS-HIGH-001" if line_count >= self.high_threshold else "FS-MOD-001"
            snippet = f"{rel}: {line_count} lines (+{over_by} over threshold)"

            findings.append(
                Finding(
                    finding_id="",  # filled below
                    type=AnalyzerType.COMPLEXITY,
                    severity=severity,
                    confidence=1.0,  # line count is deterministic
                    message=f"File has {line_count} lines (threshold: {self.threshold}, over by: {over_by})",
                    location=Location(path=rel, line_start=1, line_end=line_count),
                    fingerprint=make_fingerprint(
                        rule_id,
                        rel,
                        path.stem,  # filename without extension as symbol
                        snippet,
                    ),
                    snippet=snippet,
                    metadata={
                        "rule_id": rule_id,
                        "line_count": line_count,
                        "threshold": self.threshold,
                        "over_by": over_by,
                    },
                )
            )

        # Assign stable finding IDs (fingerprint-based)
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"fs_{f.fingerprint[7:15]}_{i:04d}")

        return findings
