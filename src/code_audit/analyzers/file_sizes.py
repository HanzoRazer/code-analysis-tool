"""File sizes analyzer — detects files that have grown too large."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Thresholds (configurable via config layer later)
_THRESHOLD = 500   # lines
_HIGH = 800        # severe threshold

# Supported language extensions
DEFAULT_EXTENSIONS: frozenset[str] = frozenset({
    # Python
    ".py",
    # JavaScript/TypeScript
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Vue
    ".vue",
    # Java/JVM
    ".java", ".kt", ".scala",
    # C#/.NET
    ".cs",
    # Go
    ".go",
    # Rust
    ".rs",
    # C/C++
    ".c", ".cpp", ".cc", ".h", ".hpp",
    # Ruby
    ".rb",
    # PHP
    ".php",
})


class FileSizesAnalyzer:
    """Finds source files exceeding line count threshold.

    Large files are harder to maintain, test, and review.
    They often indicate a need for splitting or refactoring.

    Supports: Python, JavaScript, TypeScript, Vue, Java, C#, Go, Rust, C/C++, Ruby, PHP
    """

    id: str = "file_sizes"
    version: str = "1.1.0"  # bumped for multi-language support

    def __init__(
        self,
        threshold: int = _THRESHOLD,
        high_threshold: int = _HIGH,
        extensions: Iterable[str] | None = None,
    ):
        self.threshold = threshold
        self.high_threshold = high_threshold
        self.extensions = frozenset(extensions) if extensions else DEFAULT_EXTENSIONS

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            if path.suffix not in self.extensions:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                line_count = len(lines)
            except (OSError, IOError):
                continue

            if line_count <= self.threshold:
                continue

            rel = path.relative_to(root).as_posix()
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
