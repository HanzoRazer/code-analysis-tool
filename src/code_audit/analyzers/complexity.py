"""Complexity analyzer — detects functions that are doing too much."""

from __future__ import annotations

import ast
from pathlib import Path

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# Thresholds (all configurable via config layer later)
_MODERATE = 10   # 🟡 yellow
_HIGH = 25       # 🔴 hard-mode


def _cyclomatic_complexity(node: ast.AST) -> int:
    """Count decision points in a function/method body.

    CC = 1 + number of decision branches (if/elif/for/while/and/or/with/except).
    """
    cc = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            cc += 1
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            cc += 1
        elif isinstance(child, (ast.While,)):
            cc += 1
        elif isinstance(child, ast.BoolOp):
            # each `and`/`or` adds a branch
            cc += len(child.values) - 1
        elif isinstance(child, ast.ExceptHandler):
            cc += 1
        elif isinstance(child, (ast.With, ast.AsyncWith)):
            cc += 1
    return cc


class ComplexityAnalyzer:
    """Finds functions with high cyclomatic complexity."""

    id: str = "complexity"
    version: str = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = path.relative_to(root).as_posix()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                cc = _cyclomatic_complexity(node)
                if cc < _MODERATE:
                    continue

                end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
                severity = Severity.HIGH if cc >= _HIGH else Severity.MEDIUM
                snippet = f"def {node.name}(…)  # CC={cc}"

                findings.append(
                    Finding(
                        finding_id="",  # filled below
                        type=AnalyzerType.COMPLEXITY,
                        severity=severity,
                        confidence=0.95,
                        message=f"Function '{node.name}' has cyclomatic complexity {cc}",
                        location=Location(path=rel, line_start=node.lineno, line_end=end_line),
                        fingerprint=make_fingerprint(
                            "CX-HIGH-001" if cc >= _HIGH else "CX-MOD-001",
                            rel,
                            node.name,
                            snippet,
                        ),
                        snippet=snippet,
                        metadata={"rule_id": "CX-HIGH-001" if cc >= _HIGH else "CX-MOD-001", "cc": cc},
                    )
                )

        # Assign stable finding IDs (fingerprint-based)
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"cx_{f.fingerprint[7:15]}_{i:04d}")

        return findings
