"""Runner — orchestrates analyzers, collects findings, builds RunResult."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from code_audit.contracts.load import validate_instance
from code_audit.core.discover import discover_py_files
from code_audit.insights.confidence import compute_confidence
from code_audit.insights.translator import findings_to_signals
from code_audit.model import RiskLevel
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult
from code_audit.utils.determinism import (
    is_ci_mode,
    deterministic_timestamp,
    deterministic_run_id,
    sort_findings,
    sort_signals,
)

if TYPE_CHECKING:
    from code_audit.analyzers.base import Analyzer


def run_scan(
    root: Path,
    analyzers: list[Analyzer],
    *,
    project_id: str = "",
    config: dict | None = None,
    out_dir: Path | None = None,
    emit_signals_path: str | None = None,
    ci_mode: bool = False,
    # Testing hooks for golden-fixture determinism
    _run_id: str | None = None,
    _created_at: str | None = None,
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
    # Inject deterministic values for golden-fixture testing or CI mode
    effective_ci = ci_mode or is_ci_mode()
    if _run_id is not None:
        object.__setattr__(result, "run_id", _run_id)
    elif effective_ci:
        object.__setattr__(result, "run_id", deterministic_run_id(root, ci_mode=True))
    if _created_at is not None:
        object.__setattr__(result, "created_at", _created_at)
    elif effective_ci:
        object.__setattr__(result, "created_at", deterministic_timestamp(ci_mode=True))

    # ── 5. validate output against schema ─────────────────────────────
    result_dict = result.to_dict()
    validate_instance(result_dict, "run_result.schema.json")

    # ── 6. optionally write artifacts to disk ─────────────────────────
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run_result.json").write_text(
            json.dumps(result_dict, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

        if emit_signals_path is not None:
            from code_audit import __version__

            signals_latest = {
                "schema_version": "signals_latest_v1",
                "run_id": result.run_id,
                "computed_at": result.created_at,
                "signal_logic_version": result.signal_logic_version,
                "copy_version": result.copy_version,
                "signals": signals,
            }
            validate_instance(signals_latest, "signals_latest.schema.json")
            (out_dir / emit_signals_path).write_text(
                json.dumps(signals_latest, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
    return result
