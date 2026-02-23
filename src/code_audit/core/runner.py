"""Runner — orchestrates analyzers, collects findings, builds RunResult."""

from __future__ import annotations

import json
import logging
import os
import signal as _signal
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import TYPE_CHECKING

from code_audit.contracts.load import validate_instance
from code_audit.utils.json_norm import stable_json_dumps
from code_audit.core.discover import discover_py_files
from code_audit.insights.confidence import compute_confidence
from code_audit.insights.translator import findings_to_signals
from code_audit.model import RiskLevel
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult
from code_audit.policy.thresholds import tier_from_score

if TYPE_CHECKING:
    from code_audit.analyzers.base import Analyzer

_logger = logging.getLogger(__name__)

# Default per-analyzer timeout in seconds.  Override with
# CODE_AUDIT_ANALYZER_TIMEOUT env var (0 = no limit).
_DEFAULT_ANALYZER_TIMEOUT = 300  # 5 minutes


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

    # ── 1. run every analyzer (with per-analyzer timeout) ───────────
    timeout_str = os.environ.get("CODE_AUDIT_ANALYZER_TIMEOUT", "")
    analyzer_timeout: float | None = (
        float(timeout_str) if timeout_str else _DEFAULT_ANALYZER_TIMEOUT
    )
    if analyzer_timeout == 0:
        analyzer_timeout = None  # no limit

    all_findings: list[Finding] = []
    for analyzer in analyzers:
        analyzer_id = getattr(analyzer, "id", type(analyzer).__name__)
        if analyzer_timeout is not None:
            # Run with a deadline so a single slow analyzer cannot stall
            # the entire scan indefinitely.
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(analyzer.run, root, files)
                try:
                    results = future.result(timeout=analyzer_timeout)
                    all_findings.extend(results)
                except FuturesTimeoutError:
                    _logger.warning(
                        "Analyzer '%s' timed out after %.0fs — skipped",
                        analyzer_id,
                        analyzer_timeout,
                    )
                except Exception:
                    _logger.exception(
                        "Analyzer '%s' raised an exception — skipped",
                        analyzer_id,
                    )
        else:
            all_findings.extend(analyzer.run(root, files))

    # ── 2. compute confidence score ─────────────────────────────────
    score = compute_confidence(all_findings)
    tier = tier_from_score(score)

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
    # Inject deterministic values for golden-fixture testing
    if _run_id is not None:
        object.__setattr__(result, "run_id", _run_id)
    if _created_at is not None:
        object.__setattr__(result, "created_at", _created_at)

    # ── 5. validate output against schema ─────────────────────────────
    result_dict = result.to_dict()
    validate_instance(result_dict, "run_result.schema.json")

    # ── 6. optionally write artifacts to disk ─────────────────────────
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run_result.json").write_text(
            stable_json_dumps(result_dict, ci_mode=ci_mode),
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
                stable_json_dumps(signals_latest, ci_mode=ci_mode),
                encoding="utf-8",
            )
    return result
