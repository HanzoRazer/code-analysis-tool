"""Runner — orchestrates analyzers, collects findings, builds RunResult."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from code_audit.core.discover import discover_py_files
from code_audit.insights.confidence import compute_confidence
from code_audit.insights.translator import findings_to_signals
from code_audit.model import RiskLevel
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult

if TYPE_CHECKING:
    from code_audit.analyzers.base import Analyzer


def run_scan(
    root: Path,
    analyzers: list[Analyzer],
    *,
    project_id: str = "",
    config: dict | None = None,
) -> RunResult:
    """Execute all *analyzers* against *root* and assemble a ``RunResult``.

    This is the **only** entry point that wires engine → insights → output.
    """
    scan_config = config or {}
    files = discover_py_files(
        root,
        include=scan_config.get("include"),
        exclude=scan_config.get("exclude"),
    )

    # ── 1. run every analyzer ───────────────────────────────────────
    all_findings: list[Finding] = []
    for analyzer in analyzers:
        all_findings.extend(analyzer.run(root, files))

    # ── 2. compute confidence score ─────────────────────────────────
    score = compute_confidence(all_findings)
    if score >= 75:
        tier = RiskLevel.GREEN
    elif score >= 55:
        tier = RiskLevel.YELLOW
    else:
        tier = RiskLevel.RED

    # Hard-stop red triggers (per spec)
    from code_audit.model import AnalyzerType, Severity

    for f in all_findings:
        if f.severity in {Severity.HIGH, Severity.CRITICAL} and f.type in {
            AnalyzerType.SECURITY,
            AnalyzerType.SAFETY,
            AnalyzerType.EXCEPTIONS,
        }:
            tier = RiskLevel.RED
            break

    # ── 3. translate findings → signals ─────────────────────────────
    signals = findings_to_signals(all_findings)

    # ── 4. assemble RunResult ───────────────────────────────────────
    result = RunResult(
        project_id=project_id,
        config={
            "root": str(root),
            "include": scan_config.get("include", ["**/*.py"]),
            "exclude": scan_config.get("exclude", []),
        },
        vibe_tier=tier,
        confidence_score=score,
        findings=all_findings,
        signals_snapshot=signals,
    )

    return result
