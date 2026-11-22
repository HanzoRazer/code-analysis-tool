"""Runner and schema teeth for fail-closed scan integrity."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.security import SecurityAnalyzer
from code_audit.core.runner import run_scan
from code_audit.model import AnalyzerType, RiskLevel, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.policy.thresholds import exit_code_from_tier
from code_audit.pr_clean import PrCleanError, _complete_scan
from code_audit.reports.exporters import export_markdown

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "run_result.schema.json"
CLEAN_REPO = Path(__file__).resolve().parent / "fixtures" / "repos" / "clean_project"


class _Ok:
    id = "complexity"

    def run(self, root: Path, files: list[Path]) -> list:
        return []


class _Crash:
    def __init__(self, analyzer_id: str) -> None:
        self.id = analyzer_id

    def run(self, root: Path, files: list[Path]) -> list:
        raise RuntimeError(f"{self.id} crashed")


class _JsMissing:
    id = "js_ts_security"
    languages = ("js", "ts", "tsx")

    def capability_available(self) -> bool:
        return False

    def filter_files(self, files_by_lang: dict) -> list:
        found = []
        for lang in ("js", "ts"):
            found.extend((path, lang) for path in files_by_lang.get(lang, []))
        return found

    def run(self, root: Path, files: list[Path]) -> list:
        return []

    def run_multilang(self, root: Path, files_by_lang: dict) -> list:
        return []


class _CriticalHit:
    id = "security"

    def run(self, root: Path, files: list[Path]) -> list:
        return [
            Finding(
                finding_id="F-SEC",
                type=AnalyzerType.SECURITY,
                severity=Severity.HIGH,
                confidence=0.9,
                message="hard stop",
                location=Location(path="a.py", line_start=1, line_end=1),
                fingerprint=make_fingerprint("SEC-TEST", "a.py", "x", "hard stop"),
            )
        ]


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_empty_scan_inconclusive_not_green(tmp_path: Path) -> None:
    result = run_scan(tmp_path, [_Ok()])
    assert result.vibe_tier == RiskLevel.INCONCLUSIVE
    assert result.confidence_score is None
    assert result.scan_integrity["assessable"] is False
    assert exit_code_from_tier(result.vibe_tier) == 3
    jsonschema.validate(result.to_dict(), _schema())


def test_crashing_security_analyzer_inconclusive(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(tmp_path, [_Crash("security"), _Ok()])
    assert result.vibe_tier == RiskLevel.INCONCLUSIVE
    assert result.confidence_score is None
    assert any(
        item["analyzer_id"] == "security" and item["status"] == "failed"
        for item in result.scan_integrity["degraded"]
    )


def test_missing_capability_on_eligible_js_is_inconclusive(tmp_path: Path) -> None:
    """Eligible JS/TS files no parser could read were never assessed: exit 3.

    Holds even though a Python analyzer completed. js_ts_security is now a
    critical analyzer (its HIGH findings force RED), so the reason is reported
    as critical_analyzer_missing_capability; before that change this case was
    already INCONCLUSIVE via the generic missing_capability rule.
    """
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [_Ok(), _JsMissing()])
    assert result.vibe_tier == RiskLevel.INCONCLUSIVE
    assert result.confidence_score is None
    assert exit_code_from_tier(result.vibe_tier) == 3
    assert "critical_analyzer_missing_capability:js_ts_security" in result.scan_integrity["reasons"]
    degraded = result.scan_integrity["degraded"]
    assert degraded[0]["analyzer_id"] == "js_ts_security"
    assert degraded[0]["status"] == "missing_capability"


def test_crashing_noncritical_caps_green_at_yellow(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(tmp_path, [SecurityAnalyzer(), _Crash("complexity")])
    assert result.scan_integrity["assessable"] is True
    assert result.vibe_tier == RiskLevel.YELLOW
    assert isinstance(result.confidence_score, int)


def test_clean_real_repo_still_green() -> None:
    result = run_scan(CLEAN_REPO, [ComplexityAnalyzer(), SecurityAnalyzer()])
    assert result.vibe_tier == RiskLevel.GREEN
    assert result.confidence_score is not None
    assert result.confidence_score >= 75
    assert result.scan_integrity["assessable"] is True
    assert result.scan_integrity["degraded"] == []


def test_completed_critical_high_is_red_and_discloses_degraded(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(tmp_path, [_CriticalHit(), _Crash("complexity")])
    assert result.vibe_tier == RiskLevel.RED
    assert result.confidence_score is not None
    rendered = export_markdown(result)
    assert "Incomplete coverage" in rendered
    assert "complexity" in rendered
    assert "RED" in rendered


def test_inconclusive_exit_code_is_3_not_2(tmp_path: Path) -> None:
    result = run_scan(tmp_path, [_Crash("security")])
    assert exit_code_from_tier(result.vibe_tier) == 3
    assert exit_code_from_tier(RiskLevel.RED) == 2


def test_scan_integrity_and_null_score_validate(tmp_path: Path) -> None:
    result = run_scan(tmp_path, [_Ok()])
    payload = result.to_dict()
    assert payload["summary"]["confidence_score"] is None
    assert payload["summary"]["vibe_tier"] == "inconclusive"
    assert "scan_integrity" in payload
    jsonschema.validate(payload, _schema())


def test_pr_clean_surfaces_structured_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")

    def boom(self, root: Path, files: list[Path]) -> list:
        raise RuntimeError("security down")

    monkeypatch.setattr(SecurityAnalyzer, "run", boom)
    with pytest.raises(PrCleanError) as exc:
        _complete_scan(tmp_path, "proj", None)
    message = str(exc.value)
    assert "scan incomplete" in message
    assert "scan_integrity.degraded=[" in message
    assert "security=failed" in message


def test_pr_clean_refuses_missing_parser_logged_only_at_info(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real scan, tree-sitter absent: the runner logs INFO "skipping" only."""
    from code_audit.analyzers import treesitter_base

    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("eval(x);\n")
    monkeypatch.setattr(treesitter_base, "is_available", lambda: False)
    with pytest.raises(PrCleanError, match="missing_capability"):
        _complete_scan(tmp_path, "proj", None)


class _FilterCrash(_JsMissing):
    def capability_available(self) -> bool:
        return True

    def filter_files(self, files_by_lang: dict) -> list:
        raise RuntimeError("filter crashed")


def test_filter_files_crash_is_recorded_not_raised(tmp_path: Path) -> None:
    """Eligibility runs before the analyzer; its crash must still be an outcome."""
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [SecurityAnalyzer(), _FilterCrash()])
    assert {"analyzer_id": "js_ts_security", "status": "failed"}.items() <= (
        result.scan_integrity["degraded"][0].items()
    )
    assert result.vibe_tier != RiskLevel.GREEN


def test_critical_filter_files_crash_is_inconclusive(tmp_path: Path) -> None:
    class _CriticalFilterCrash(_FilterCrash):
        id = "security"

    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [_Ok(), _CriticalFilterCrash()])
    assert result.vibe_tier == RiskLevel.INCONCLUSIVE
    assert exit_code_from_tier(result.vibe_tier) == 3


def test_unparseable_eligible_file_degrades_and_keeps_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A per-file parse failure is not an "ok" analyzer; found issues are kept."""
    from code_audit.analyzers import treesitter_base
    from code_audit.analyzers.treesitter_base import SourceFile, TreeSitterAnalyzerBase

    class _Partial(TreeSitterAnalyzerBase):
        id = "js_ts_security"

        def _parse_file(self, path: Path, language: str) -> SourceFile | None:
            if path.name == "broken.js":
                return None
            return SourceFile(path=path, language=language, text="", source=b"", tree=None)

        def analyze_file(self, source_file: SourceFile, root: Path) -> list:
            return [
                Finding(
                    finding_id="F-JS",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.LOW,
                    confidence=0.9,
                    message="js finding",
                    location=Location(path=source_file.path.name, line_start=1, line_end=1),
                    fingerprint=make_fingerprint("JS-TEST", source_file.path.name, "x", "y"),
                )
            ]

    monkeypatch.setattr(treesitter_base, "is_available", lambda: True)
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "good.js").write_text("const x = 1;\n")
    (tmp_path / "broken.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [SecurityAnalyzer(), _Partial()])
    assert [f.message for f in result.findings] == ["js finding"]
    degraded = result.scan_integrity["degraded"]
    assert [(d["analyzer_id"], d["status"]) for d in degraded] == [("js_ts_security", "failed")]
    assert result.vibe_tier != RiskLevel.GREEN


# ── JS/TS security: same fail-closed treatment as Python security ──────────


class _JsHigh:
    id = "js_ts_security"

    def run(self, root: Path, files: list[Path]) -> list:
        return [
            Finding(
                finding_id="F-JS",
                type=AnalyzerType.JS_TS_SECURITY,
                severity=Severity.HIGH,
                confidence=0.9,
                message="eval() executes arbitrary code",
                location=Location(path="app.js", line_start=2, line_end=2),
                fingerprint=make_fingerprint("SEC_EVAL_JS_001", "app.js", "eval", "eval"),
            )
        ]


def test_completed_js_ts_high_is_red(tmp_path: Path) -> None:
    """A completed HIGH JS/TS security finding forces RED, like Python security.

    Before: JS_TS_SECURITY was outside the hard-stop set, so eval() scored
    GREEN 77 with exit 0.
    """
    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(tmp_path, [_Ok(), _JsHigh()])
    assert result.vibe_tier == RiskLevel.RED
    assert exit_code_from_tier(result.vibe_tier) == 2


def test_real_js_eval_is_red(tmp_path: Path) -> None:
    """End to end with the real tree-sitter analyzer (the reproduced P1)."""
    pytest.importorskip("tree_sitter_javascript")
    from code_audit.analyzers.js_ts_security import JsTsSecurityPreviewAnalyzer

    (tmp_path / "app.js").write_text(
        "function run(code) {\n  return eval(code);\n}\nmodule.exports = { run };\n",
        encoding="utf-8",
    )
    result = run_scan(tmp_path, [JsTsSecurityPreviewAnalyzer()])
    assert any(f["metadata"].get("rule_id") == "SEC_EVAL_JS_001" for f in result.to_dict()["findings_raw"])
    assert result.vibe_tier == RiskLevel.RED


def test_crashing_js_ts_security_inconclusive(tmp_path: Path) -> None:
    """If its findings force RED, failing to run it leaves the scan unassessable."""
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [_Ok(), _Crash("js_ts_security")])
    assert result.vibe_tier == RiskLevel.INCONCLUSIVE
    assert exit_code_from_tier(result.vibe_tier) == 3
    assert "critical_analyzer_failed:js_ts_security" in result.scan_integrity["reasons"]


def test_hard_stop_finding_types_are_critical_analyzers() -> None:
    """The two sets drifted once (JS_TS_SECURITY); keep them in lockstep."""
    from code_audit.core.runner import HARD_STOP_FINDING_TYPES
    from code_audit.core.scan_integrity import CRITICAL_ANALYZER_IDS

    missing = {t.value for t in HARD_STOP_FINDING_TYPES} - CRITICAL_ANALYZER_IDS
    assert not missing, f"hard-stop types without a critical analyzer: {sorted(missing)}"


def test_v2_schema_requires_scan_integrity(tmp_path: Path) -> None:
    """No integrity-free GREEN: a v2 result must carry its integrity evidence.

    The single producer (the runner) always emits it, so requiring it closes
    the path where a consumer trusts a GREEN that never proved assessability.
    interpret_stored_result() keeps "missing = unverified" for v1/legacy only.
    """
    (tmp_path / "a.py").write_text("x = 1\n")
    payload = run_scan(tmp_path, [_Ok()]).to_dict()
    jsonschema.validate(payload, _schema())
    payload.pop("scan_integrity")
    with pytest.raises(jsonschema.ValidationError, match="scan_integrity"):
        jsonschema.validate(payload, _schema())
