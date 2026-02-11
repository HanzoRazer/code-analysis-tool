"""Integration tests for the scan pipeline (code_audit.core.runner)."""

from __future__ import annotations

import json
import textwrap
import sys
from pathlib import Path

import jsonschema
import pytest

# Ensure the src layout is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.exceptions import ExceptionsAnalyzer
from code_audit.core.runner import run_scan
from code_audit.model import Severity, AnalyzerType

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "run_result.schema.json"


@pytest.fixture()
def sample_project(tmp_path: Path) -> Path:
    """Create a minimal Python project with known issues."""
    code = textwrap.dedent("""\
        def simple():
            return 1

        def complex_func(x, y, z, a, b, c, d, e, f, g):
            if x:
                if y:
                    if z:
                        if a:
                            if b:
                                if c:
                                    if d:
                                        if e:
                                            if f:
                                                if g:
                                                    return 1
            return 0

        def bad_error_handling():
            try:
                open("missing.txt")
            except:
                pass
    """)
    (tmp_path / "app.py").write_text(code)
    return tmp_path


class TestRunScan:
    """End-to-end scan pipeline tests."""

    def test_produces_valid_run_result_json(self, sample_project: Path) -> None:
        """run_scan output must validate against run_result.schema.json."""
        analyzers = [ComplexityAnalyzer(), ExceptionsAnalyzer()]
        result = run_scan(sample_project, analyzers, project_id="test-project")
        result_dict = result.to_dict()

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(result_dict, schema)

    def test_detects_complexity(self, sample_project: Path) -> None:
        """Complexity analyzer must flag the deeply-nested function."""
        analyzers = [ComplexityAnalyzer()]
        result = run_scan(sample_project, analyzers)

        complex_findings = [
            f for f in result.findings if f.type == AnalyzerType.COMPLEXITY
        ]
        assert len(complex_findings) >= 1
        names = [f.metadata.get("rule_id") for f in complex_findings]
        assert any(r in names for r in ("CX-MOD-001", "CX-HIGH-001"))

    def test_detects_bare_except(self, sample_project: Path) -> None:
        """Exceptions analyzer must flag the bare except clause."""
        analyzers = [ExceptionsAnalyzer()]
        result = run_scan(sample_project, analyzers)

        exc_findings = [
            f for f in result.findings if f.type == AnalyzerType.EXCEPTIONS
        ]
        assert len(exc_findings) >= 1
        rule_ids = [f.metadata.get("rule_id") for f in exc_findings]
        assert "EXC-BARE-001" in rule_ids

    def test_confidence_score_is_integer(self, sample_project: Path) -> None:
        """Confidence score must be an int (schema says ``integer``)."""
        analyzers = [ComplexityAnalyzer(), ExceptionsAnalyzer()]
        result = run_scan(sample_project, analyzers)
        assert isinstance(result.confidence_score, int)
        assert 0 <= result.confidence_score <= 100

    def test_signals_reference_finding_ids(self, sample_project: Path) -> None:
        """Every signal's evidence.finding_ids must exist in findings_raw."""
        analyzers = [ComplexityAnalyzer(), ExceptionsAnalyzer()]
        result = run_scan(sample_project, analyzers)
        result_dict = result.to_dict()

        raw_ids = {f["finding_id"] for f in result_dict["findings_raw"]}
        for signal in result_dict["signals_snapshot"]:
            for fid in signal["evidence"]["finding_ids"]:
                assert fid in raw_ids, f"Signal references unknown finding {fid}"

    def test_clean_project_scores_high(self, tmp_path: Path) -> None:
        """A project with only clean code should score ≥ 75 (green)."""
        (tmp_path / "clean.py").write_text("def greet():\n    return 'hi'\n")
        analyzers = [ComplexityAnalyzer(), ExceptionsAnalyzer()]
        result = run_scan(tmp_path, analyzers)
        assert result.confidence_score >= 75
        assert result.vibe_tier.value == "green"
