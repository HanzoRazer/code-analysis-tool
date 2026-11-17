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


def test_missing_capability_on_eligible_js_not_green(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "app.js").write_text("const x = 1;\n")
    result = run_scan(tmp_path, [_Ok(), _JsMissing()])
    assert result.vibe_tier != RiskLevel.GREEN
    assert result.vibe_tier == RiskLevel.YELLOW
    assert result.confidence_score is not None
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
    assert "skipped" in message
    assert "scan_integrity.degraded:" in message
    assert "security=failed" in message
