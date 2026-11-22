"""Runner — orchestrates analyzers, collects findings, builds RunResult."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import json
import logging
import os
from pathlib import Path
import signal as _signal
import time
from typing import TYPE_CHECKING

from code_audit.contracts.load import validate_instance
from code_audit.core.discover import discover_py_files, discover_source_files
from code_audit.core.scan_integrity import (
    CRITICAL_ANALYZER_IDS,
    AnalyzerIncomplete,
    AnalyzerOutcome,
    AnalyzerStatus,
    MissingAnalyzerCapability,
    evaluate_scan_integrity,
)
from code_audit.insights.confidence import compute_confidence
from code_audit.insights.translator import findings_to_signals
from code_audit.model import AnalyzerType, RiskLevel
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult
from code_audit.policy.thresholds import tier_from_score
from code_audit.utils.json_norm import stable_json_dumps

if TYPE_CHECKING:
    from code_audit.analyzers.base import Analyzer

_logger = logging.getLogger(__name__)

# Default per-analyzer timeout in seconds.  Override with
# CODE_AUDIT_ANALYZER_TIMEOUT env var (0 = no limit).
_DEFAULT_ANALYZER_TIMEOUT = 300  # 5 minutes


# A completed HIGH/CRITICAL finding of these types forces RED. Every type here
# must also be a critical analyzer in scan_integrity.CRITICAL_ANALYZER_IDS:
# if a finding is severe enough to force RED, failing to run the analyzer that
# finds it leaves the scan unassessable (tests/test_scan_integrity_runner.py).
HARD_STOP_FINDING_TYPES = frozenset({
    AnalyzerType.SECURITY,
    AnalyzerType.SAFETY,
    AnalyzerType.EXCEPTIONS,
    AnalyzerType.JS_TS_SECURITY,
})

def _analyzer_id(analyzer: Analyzer) -> str:
    return str(getattr(analyzer, "id", type(analyzer).__name__))


def _targets_python(analyzer: Analyzer) -> bool:
    languages = getattr(analyzer, "languages", None)
    if languages is None:
        return True
    return any(lang in {"py", "python"} for lang in languages)


def _is_multilang(analyzer: Analyzer) -> bool:
    return callable(getattr(analyzer, "run_multilang", None))


def _capability_missing(analyzer: Analyzer) -> bool:
    probe = getattr(analyzer, "capability_available", None)
    if not callable(probe):
        return False
    try:
        return not bool(probe())
    except Exception:
        return True


def _eligible_ml_files(analyzer: Analyzer, files_by_lang: dict[str, list[Path]]) -> list[Path]:
    filter_files = getattr(analyzer, "filter_files", None)
    if callable(filter_files):
        return [path for path, _language in filter_files(files_by_lang)]
    found: list[Path] = []
    for key in ("js", "ts"):
        found.extend(files_by_lang.get(key) or [])
    return found


def _ml_eligibility(
    analyzer: Analyzer, files_by_lang: dict[str, list[Path]], analyzer_id: str
) -> list[Path] | None:
    """Eligible JS/TS files, or ``None`` when the analyzer's own filter crashed.

    Runs before the analyzer itself, so it needs its own guard: an exception
    here must become a ``failed`` outcome, not escape ``run_scan()``.
    """
    try:
        return _eligible_ml_files(analyzer, files_by_lang)
    except Exception:
        _logger.exception(
            "Multi-lang analyzer '%s' raised an exception — skipped", analyzer_id
        )
        return None


def _invoke(
    fn,
    args: tuple,
    *,
    timeout: float | None,
    analyzer_id: str,
    multilang: bool,
) -> list[Finding]:
    """Run one analyzer phase. Timeout and crash keep the historical warning text."""
    label = "Multi-lang analyzer" if multilang else "Analyzer"
    try:
        if timeout is None:
            return list(fn(*args))
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn, *args)
            return list(future.result(timeout=timeout))
    except FuturesTimeoutError:
        _logger.warning(
            "%s '%s' timed out after %.0fs — skipped",
            label,
            analyzer_id,
            timeout,
        )
        raise
    except MissingAnalyzerCapability:
        raise
    except AnalyzerIncomplete as exc:
        _logger.warning(
            "%s '%s' incomplete: %d eligible file(s) not assessed",
            label,
            analyzer_id,
            len(exc.unassessed),
        )
        raise
    except Exception:
        _logger.exception(
            "%s '%s' raised an exception — skipped",
            label,
            analyzer_id,
        )
        raise


def _outcome(
    analyzer_id: str,
    critical: bool,
    status: AnalyzerStatus,
    started: float,
) -> AnalyzerOutcome:
    return AnalyzerOutcome(
        analyzer_id=analyzer_id,
        status=status,
        is_critical=critical,
        duration_s=time.perf_counter() - started,
    )


def _run_analyzer(
    analyzer: Analyzer,
    root: Path,
    files_by_lang: dict[str, list[Path]],
    *,
    enable_js_ts: bool,
    timeout: float | None,
) -> tuple[list[Finding], AnalyzerOutcome]:
    """Run one analyzer and record why it did or did not assess its files."""
    analyzer_id = _analyzer_id(analyzer)
    critical = analyzer_id in CRITICAL_ANALYZER_IDS
    started = time.perf_counter()
    py_files = list(files_by_lang.get("py") or [])
    multilang = _is_multilang(analyzer)
    py_eligible = _targets_python(analyzer) and bool(py_files)

    def finish(status: AnalyzerStatus) -> AnalyzerOutcome:
        return _outcome(analyzer_id, critical, status, started)

    ml_files = (
        _ml_eligibility(analyzer, files_by_lang, analyzer_id)
        if multilang and enable_js_ts
        else []
    )
    if ml_files is None:
        return [], finish("failed")
    ml_eligible = bool(ml_files)

    if multilang and not enable_js_ts and not py_eligible:
        return [], finish("not_scheduled")
    if not py_eligible and not ml_eligible:
        return [], finish("not_applicable")
    if ml_eligible and _capability_missing(analyzer):
        _logger.info("tree-sitter not available — skipping %s", analyzer_id)
        return [], finish("missing_capability")

    findings: list[Finding] = []
    try:
        if py_eligible:
            findings.extend(_invoke(
                analyzer.run, (root, py_files),
                timeout=timeout, analyzer_id=analyzer_id, multilang=False,
            ))
        if ml_eligible:
            findings.extend(_invoke(
                analyzer.run_multilang, (root, files_by_lang),
                timeout=timeout, analyzer_id=analyzer_id, multilang=True,
            ))
    except MissingAnalyzerCapability:
        return findings, finish("missing_capability")
    except AnalyzerIncomplete as exc:
        findings.extend(exc.findings)
        return findings, finish("failed")
    except Exception:
        return findings, finish("failed")
    return findings, finish("ok")


def run_scan(
    root: Path,
    analyzers: list[Analyzer],
    *,
    project_id: str = "",
    config: dict | None = None,
    out_dir: Path | None = None,
    emit_signals_path: str | None = None,
    ci_mode: bool = False,
    enable_js_ts: bool = True,
    # Testing hooks for golden-fixture determinism
    _run_id: str | None = None,
    _created_at: str | None = None,
) -> RunResult:
    """Execute all *analyzers* against *root* and assemble a ``RunResult``.

    This is the **only** entry point that wires engine → insights → output.
    """
    scan_config = config or {}
    files_by_lang = discover_source_files(
        root,
        include=scan_config.get("include"),
        exclude=scan_config.get("exclude"),
        enable_js_ts=enable_js_ts,
    )

    # ── 1. run every analyzer (with per-analyzer timeout) ───────────
    timeout_str = os.environ.get("CODE_AUDIT_ANALYZER_TIMEOUT", "")
    analyzer_timeout: float | None = (
        float(timeout_str) if timeout_str else _DEFAULT_ANALYZER_TIMEOUT
    )
    if analyzer_timeout == 0:
        analyzer_timeout = None  # no limit

    all_findings: list[Finding] = []
    outcomes: list[AnalyzerOutcome] = []
    for analyzer in analyzers:
        produced, outcome = _run_analyzer(
            analyzer,
            root,
            files_by_lang,
            enable_js_ts=enable_js_ts,
            timeout=analyzer_timeout,
        )
        all_findings.extend(produced)
        outcomes.append(outcome)

    # ── 2. compute confidence score ─────────────────────────────────
    # Contract hygiene: validate each finding against finding schema.
    from code_audit.contracts.validate import ContractValidationError, validate_finding

    for f in all_findings:
        try:
            validate_finding(f.to_dict())
        except ContractValidationError:
            _logger.warning(
                "Finding failed contract validation (rule: %s, path: %s)",
                f.metadata.get("rule_id", "?"),
                f.location.path,
                exc_info=True,
            )

    score: int | None = compute_confidence(all_findings)
    tier = tier_from_score(score)

    # Hard-stop red triggers (per spec). A completed critical finding
    # outranks an inconclusive scan: the hit is more actionable than
    # "we could not finish looking."
    from code_audit.model import Severity

    red_hit = False
    for f in all_findings:
        if f.severity in {Severity.HIGH, Severity.CRITICAL} and f.type in HARD_STOP_FINDING_TYPES:
            red_hit = True
            tier = RiskLevel.RED
            break

    files_scanned = sum(len(paths) for paths in files_by_lang.values())
    integrity = evaluate_scan_integrity(files_scanned, outcomes)
    if red_hit:
        tier = RiskLevel.RED
    elif not integrity.assessable:
        tier = RiskLevel.INCONCLUSIVE
        score = None
    elif integrity.degraded and tier == RiskLevel.GREEN:
        tier = RiskLevel.YELLOW

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
        scan_integrity=integrity.to_dict(),
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
