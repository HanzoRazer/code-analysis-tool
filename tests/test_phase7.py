"""Tests for Phase 7 — Reports, Dashboard, and ML Experimental modules."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from code_audit.model import AnalyzerType, RiskLevel, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.model.run_result import RunResult


# ── helpers ──────────────────────────────────────────────────────────


def _make_finding(
    *,
    severity: Severity = Severity.MEDIUM,
    atype: AnalyzerType = AnalyzerType.COMPLEXITY,
    path: str = "module.py",
    line: int = 10,
    message: str = "test finding",
    rule_id: str = "TEST-001",
) -> Finding:
    snippet = f"# line {line}"
    return Finding(
        finding_id=f"t_{line:04d}",
        type=atype,
        severity=severity,
        confidence=0.90,
        message=message,
        location=Location(path=path, line_start=line, line_end=line),
        fingerprint=make_fingerprint(rule_id, path, str(line), snippet),
        snippet=snippet,
        metadata={"rule_id": rule_id},
    )


def _make_run_result(findings: list[Finding] | None = None) -> RunResult:
    """Build a minimal RunResult for testing."""
    if findings is None:
        findings = [
            _make_finding(severity=Severity.CRITICAL, line=1, message="critical bug"),
            _make_finding(severity=Severity.HIGH, line=2, message="high issue"),
            _make_finding(severity=Severity.MEDIUM, line=3, message="medium issue"),
            _make_finding(severity=Severity.LOW, line=4, message="low issue"),
            _make_finding(severity=Severity.INFO, line=5, message="info note"),
        ]
    return RunResult(
        run_id="test-run-001",
        project_id="test-project",
        created_at="2025-01-15T00:00:00Z",
        tool_version="1.0.0",
        engine_version="1.0.0",
        signal_logic_version="1.0.0",
        copy_version="1.0.0",
        config={},
        vibe_tier=RiskLevel.YELLOW,
        confidence_score=60,
        findings=findings,
        signals_snapshot=[],
        snippet_policy="first_line",
    )


# ════════════════════════════════════════════════════════════════════
# Trend Analysis
# ════════════════════════════════════════════════════════════════════


class TestTrendAnalysis:
    """Tests for reports.trend_analysis module."""

    def test_load_trend_data_empty_dir(self, tmp_path: Path):
        from code_audit.reports.trend_analysis import load_trend_data

        summaries = load_trend_data(tmp_path)
        assert summaries == []

    def test_load_trend_data_nonexistent(self, tmp_path: Path):
        from code_audit.reports.trend_analysis import load_trend_data

        result = load_trend_data(tmp_path / "nope")
        assert result == []

    def test_load_trend_data_single_snapshot(self, tmp_path: Path):
        from code_audit.reports.trend_analysis import load_trend_data

        snap = {
            "name": "baseline",
            "created_at": "2025-01-01T00:00:00Z",
            "debt_count": 3,
            "items": [
                {"debt_type": "god_class", "path": "a.py"},
                {"debt_type": "god_class", "path": "b.py"},
                {"debt_type": "long_method", "path": "c.py"},
            ],
        }
        (tmp_path / "snap1.json").write_text(json.dumps(snap))
        summaries = load_trend_data(tmp_path)
        assert len(summaries) == 1
        assert summaries[0].name == "baseline"
        assert summaries[0].total_items == 3
        assert summaries[0].by_type["god_class"] == 2

    def test_load_trend_data_multiple_sorted(self, tmp_path: Path):
        from code_audit.reports.trend_analysis import load_trend_data

        for i, (name, date, count) in enumerate([
            ("v1", "2025-01-01T00:00:00Z", 10),
            ("v3", "2025-03-01T00:00:00Z", 6),
            ("v2", "2025-02-01T00:00:00Z", 8),
        ]):
            snap = {
                "name": name,
                "created_at": date,
                "debt_count": count,
                "items": [{"debt_type": "todo"} for _ in range(count)],
            }
            (tmp_path / f"snap_{i}.json").write_text(json.dumps(snap))

        summaries = load_trend_data(tmp_path)
        assert len(summaries) == 3
        # Should be sorted by created_at
        assert summaries[0].name == "v1"
        assert summaries[1].name == "v2"
        assert summaries[2].name == "v3"

    def test_load_trend_data_skips_bad_json(self, tmp_path: Path):
        from code_audit.reports.trend_analysis import load_trend_data

        (tmp_path / "good.json").write_text(json.dumps({
            "name": "ok",
            "created_at": "2025-01-01",
            "debt_count": 1,
            "items": [{"debt_type": "todo"}],
        }))
        (tmp_path / "bad.json").write_text("NOT JSON{{{{")
        summaries = load_trend_data(tmp_path)
        assert len(summaries) == 1

    def test_compute_trend_improving(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            compute_trend,
        )

        summaries = [
            SnapshotSummary("v1", "2025-01-01", 10, {}),
            SnapshotSummary("v2", "2025-02-01", 7, {}),
            SnapshotSummary("v3", "2025-03-01", 5, {}),
        ]
        trend = compute_trend(summaries)
        assert trend.direction == "improving"
        assert trend.delta == -5
        assert trend.peak == 10
        assert trend.trough == 5

    def test_compute_trend_worsening(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            compute_trend,
        )

        summaries = [
            SnapshotSummary("v1", "2025-01-01", 5, {}),
            SnapshotSummary("v2", "2025-02-01", 12, {}),
        ]
        trend = compute_trend(summaries)
        assert trend.direction == "worsening"
        assert trend.delta == 7

    def test_compute_trend_stable(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            compute_trend,
        )

        summaries = [
            SnapshotSummary("v1", "2025-01-01", 8, {}),
            SnapshotSummary("v2", "2025-02-01", 8, {}),
        ]
        trend = compute_trend(summaries)
        assert trend.direction == "stable"
        assert trend.delta == 0

    def test_compute_trend_insufficient_data(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            compute_trend,
        )

        summaries = [SnapshotSummary("v1", "2025-01-01", 5, {})]
        trend = compute_trend(summaries)
        assert trend.direction == "insufficient_data"

    def test_compute_trend_empty(self):
        from code_audit.reports.trend_analysis import compute_trend

        trend = compute_trend([])
        assert trend.direction == "insufficient_data"
        assert trend.delta == 0
        assert trend.peak == 0
        assert trend.trough == 0

    def test_render_trend_markdown(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            TrendReport,
            render_trend_markdown,
        )

        trend = TrendReport(
            snapshots=[
                SnapshotSummary("v1", "2025-01-01T00:00:00Z", 10, {"todo": 6, "god_class": 4}),
                SnapshotSummary("v2", "2025-02-01T00:00:00Z", 7, {"todo": 4, "god_class": 3}),
            ],
            direction="improving",
            delta=-3,
            peak=10,
            trough=7,
        )
        md = render_trend_markdown(trend)
        assert "# Technical Debt Trend Report" in md
        assert "IMPROVING" in md
        assert "Timeline" in md
        assert "v1" in md
        assert "v2" in md
        assert "Current Composition" in md

    def test_render_trend_markdown_empty(self):
        from code_audit.reports.trend_analysis import TrendReport, render_trend_markdown

        trend = TrendReport(
            snapshots=[], direction="insufficient_data", delta=0, peak=0, trough=0,
        )
        md = render_trend_markdown(trend)
        assert "No snapshots found" in md

    def test_render_trend_json(self):
        from code_audit.reports.trend_analysis import (
            SnapshotSummary,
            TrendReport,
            render_trend_json,
        )

        trend = TrendReport(
            snapshots=[
                SnapshotSummary("v1", "2025-01-01", 10, {}),
                SnapshotSummary("v2", "2025-02-01", 8, {}),
            ],
            direction="improving",
            delta=-2,
            peak=10,
            trough=8,
        )
        data = json.loads(render_trend_json(trend))
        assert data["direction"] == "improving"
        assert data["delta"] == -2
        assert len(data["snapshots"]) == 2

    def test_sparkline_output(self):
        from code_audit.reports.trend_analysis import _ascii_sparkline

        result = _ascii_sparkline([1, 3, 5, 7, 9])
        assert len(result) == 5
        # All chars should be in the spark charset
        assert all(c in " ▁▂▃▄▅▆▇█" for c in result)

    def test_sparkline_empty(self):
        from code_audit.reports.trend_analysis import _ascii_sparkline

        assert _ascii_sparkline([]) == ""

    def test_sparkline_uniform(self):
        from code_audit.reports.trend_analysis import _ascii_sparkline

        result = _ascii_sparkline([5, 5, 5])
        assert len(result) == 3


# ════════════════════════════════════════════════════════════════════
# Exporters
# ════════════════════════════════════════════════════════════════════


class TestExporters:
    """Tests for reports.exporters module."""

    def test_export_json(self):
        from code_audit.reports.exporters import export_json

        result = _make_run_result()
        output = export_json(result)
        data = json.loads(output)
        assert "run" in data or "findings" in data
        # Valid JSON was produced

    def test_export_markdown(self):
        from code_audit.reports.exporters import export_markdown

        result = _make_run_result()
        md = export_markdown(result, top_n=3)
        assert "# Scan Results" in md
        assert "CRITICAL" in md
        assert "HIGH" in md
        assert "By Severity" in md
        assert "Top 3 Findings" in md

    def test_export_markdown_empty(self):
        from code_audit.reports.exporters import export_markdown

        result = _make_run_result(findings=[])
        md = export_markdown(result)
        assert "# Scan Results" in md
        assert "Findings:** 0" in md

    def test_export_html_has_structure(self):
        from code_audit.reports.exporters import export_html

        result = _make_run_result()
        html = export_html(result, top_n=5)
        assert "<!DOCTYPE html>" in html
        assert "<table>" in html
        assert "CRITICAL" in html
        assert "badge" in html

    def test_export_html_severity_colors(self):
        from code_audit.reports.exporters import export_html

        result = _make_run_result()
        html = export_html(result)
        # Check that at least one severity color is embedded
        assert "#dc3545" in html or "#fd7e14" in html

    def test_export_html_escapes_html(self):
        from code_audit.reports.exporters import export_html

        findings = [
            _make_finding(message="test <script>alert('xss')</script>"),
        ]
        result = _make_run_result(findings=findings)
        html = export_html(result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_export_result_json(self):
        from code_audit.reports.exporters import export_result

        result = _make_run_result()
        output = export_result(result, "json")
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_export_result_markdown(self):
        from code_audit.reports.exporters import export_result

        result = _make_run_result()
        output = export_result(result, "markdown")
        assert "# Scan Results" in output

    def test_export_result_md_alias(self):
        from code_audit.reports.exporters import export_result

        result = _make_run_result()
        output = export_result(result, "md")
        assert "# Scan Results" in output

    def test_export_result_html(self):
        from code_audit.reports.exporters import export_result

        result = _make_run_result()
        output = export_result(result, "html")
        assert "<!DOCTYPE html>" in output

    def test_export_result_unknown_format(self):
        from code_audit.reports.exporters import export_result

        result = _make_run_result()
        with pytest.raises(ValueError, match="Unknown export format"):
            export_result(result, "csv")


# ════════════════════════════════════════════════════════════════════
# Dashboard
# ════════════════════════════════════════════════════════════════════


class TestDashboard:
    """Tests for reports.dashboard module."""

    def test_render_dashboard_has_sections(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(result)
        assert "CODE AUDIT DASHBOARD" in dash
        assert "SEVERITY BREAKDOWN" in dash
        assert "CATEGORY BREAKDOWN" in dash
        assert "FILE HOTSPOTS" in dash
        assert "═" in dash

    def test_render_dashboard_shows_score(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(result)
        assert "60/100" in dash

    def test_render_dashboard_empty_findings(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result(findings=[])
        dash = render_dashboard(result)
        assert "CODE AUDIT DASHBOARD" in dash
        # Should not crash on empty findings

    def test_render_dashboard_with_trend(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(
            result,
            trend_direction="improving",
            trend_delta=-5,
        )
        assert "TREND" in dash
        assert "IMPROVING" in dash

    def test_render_dashboard_custom_width(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(result, width=40)
        lines = dash.split("\n")
        # Header line should match width
        assert lines[0] == "═" * 40

    def test_render_dashboard_project_id(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(result)
        assert "test-project" in dash

    def test_render_dashboard_red_signals(self):
        from code_audit.reports.dashboard import render_dashboard

        result = RunResult(
            run_id="r1",
            project_id="p1",
            created_at="2025-01-15",
            tool_version="1.0.0",
            engine_version="1.0.0",
            signal_logic_version="1.0.0",
            copy_version="1.0.0",
            config={},
            vibe_tier=RiskLevel.RED,
            confidence_score=30,
            findings=[],
            signals_snapshot=[
                {"type": "complexity", "risk_level": "red", "headline": "Too complex"},
            ],
            snippet_policy="first_line",
        )
        dash = render_dashboard(result)
        assert "RED SIGNAL" in dash
        assert "Too complex" in dash

    def test_render_dashboard_severity_bars(self):
        from code_audit.reports.dashboard import render_dashboard

        result = _make_run_result()
        dash = render_dashboard(result)
        assert "█" in dash  # At least one severity bar should be drawn


# ════════════════════════════════════════════════════════════════════
# Feature Extraction
# ════════════════════════════════════════════════════════════════════


class TestFeatureExtraction:
    """Tests for ml.feature_extraction module."""

    def test_extract_simple_file(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        code = textwrap.dedent("""\
            import os
            import sys

            X = 10

            def hello(name):
                # greet
                return f"Hello, {name}"

            def add(a, b):
                return a + b

            class Foo:
                pass
        """)
        f = tmp_path / "sample.py"
        f.write_text(code)
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        assert ff.function_count == 2
        assert ff.class_count == 1
        assert ff.import_count == 2
        assert ff.global_var_count >= 1
        assert ff.line_count > 0
        assert ff.comment_density > 0.0

    def test_extract_returns_none_for_syntax_error(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        f = tmp_path / "bad.py"
        f.write_text("def foo(::\n")
        assert extract_file_features(f, root=tmp_path) is None

    def test_extract_returns_none_for_missing_file(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        assert extract_file_features(tmp_path / "nope.py", root=tmp_path) is None

    def test_feature_vector_length(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        f = tmp_path / "x.py"
        f.write_text("x = 1\n")
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        vec = ff.feature_vector()
        assert len(vec) == 8
        assert all(isinstance(v, float) for v in vec)

    def test_function_features_extracted(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        code = textwrap.dedent("""\
            def complex_func(a, b, c):
                if a:
                    for x in b:
                        if x > 0:
                            return x
                return c
        """)
        f = tmp_path / "func.py"
        f.write_text(code)
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        assert len(ff.functions) == 1
        func = ff.functions[0]
        assert func.name == "complex_func"
        assert func.param_count == 3
        assert func.complexity > 1
        assert func.return_count == 2

    def test_extract_batch(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_batch

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        (tmp_path / "c.py").write_text("def bad(::\n")  # syntax error
        results = extract_batch(
            tmp_path,
            [tmp_path / "a.py", tmp_path / "b.py", tmp_path / "c.py"],
        )
        # c.py should be skipped
        assert len(results) == 2

    def test_to_dict(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        f = tmp_path / "d.py"
        f.write_text("def foo(): pass\n")
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        d = ff.to_dict()
        assert "path" in d
        assert "line_count" in d
        assert "function_count" in d
        assert isinstance(d["functions"], list)

    def test_comment_density_computed(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        code = "# comment 1\n# comment 2\nx = 1\n"
        f = tmp_path / "commented.py"
        f.write_text(code)
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        # 2 comment lines out of 3 total lines
        assert abs(ff.comment_density - 2 / 3) < 0.01

    def test_relative_path_with_root(self, tmp_path: Path):
        from code_audit.ml.feature_extraction import extract_file_features

        sub = tmp_path / "pkg"
        sub.mkdir()
        f = sub / "mod.py"
        f.write_text("x = 1\n")
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        assert ff.path == "pkg\\mod.py" or ff.path == "pkg/mod.py"


# ════════════════════════════════════════════════════════════════════
# Bug Predictor
# ════════════════════════════════════════════════════════════════════


class TestBugPredictor:
    """Tests for ml.bug_predictor module."""

    def test_predict_file_clean_code(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        code = textwrap.dedent("""\
            # Simple clean module.
            # Well documented.

            def greet(name: str) -> str:
                '''Greet someone.'''
                return f"Hello, {name}"
        """)
        f = tmp_path / "clean.py"
        f.write_text(code)
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        pred = BugPredictor().predict_file(ff)
        assert pred.probability < 0.3  # clean code = low probability

    def test_predict_file_complex_code(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        # Generate highly complex code
        code_lines = ["# complex module\n"]
        code_lines.append("GLOBAL_A = 1\nGLOBAL_B = 2\nGLOBAL_C = 3\n")
        code_lines.append("def monster(a, b, c, d, e, f, g):\n")
        # Add many branches to boost complexity
        for i in range(15):
            code_lines.append(f"    if a > {i}:\n")
            code_lines.append(f"        pass\n")
        code_lines.append("    return a\n")
        # Add lots of lines to boost line_count score
        for i in range(200):
            code_lines.append(f"# filler line {i}\n")

        f = tmp_path / "complex.py"
        f.write_text("".join(code_lines))
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        pred = BugPredictor().predict_file(ff)
        assert pred.probability > 0.15  # complex code = higher probability
        assert len(pred.risk_factors) > 0

    def test_predict_returns_sorted(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor

        (tmp_path / "small.py").write_text("x = 1\n")
        big_code = "\n".join(
            [f"GLOB_{i} = {i}" for i in range(10)]
            + ["def big():\n    " + "\n    ".join(f"if x > {i}: pass" for i in range(15))]
            + ["\n    return 0"]
        )
        (tmp_path / "big.py").write_text(big_code)
        predictions = BugPredictor().predict(
            tmp_path,
            [tmp_path / "small.py", tmp_path / "big.py"],
        )
        assert len(predictions) == 2
        # Sorted by probability descending
        assert predictions[0].probability >= predictions[1].probability

    def test_predict_from_features(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        (tmp_path / "a.py").write_text("x = 1\n")
        ff = extract_file_features(tmp_path / "a.py", root=tmp_path)
        assert ff is not None
        preds = BugPredictor().predict_from_features([ff])
        assert len(preds) == 1
        assert 0.0 <= preds[0].probability <= 1.0

    def test_risk_factors_populated(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        code = "GLOBAL = 1\n" * 5 + "x = 1\n"
        f = tmp_path / "globals.py"
        f.write_text(code)
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        pred = BugPredictor().predict_file(ff)
        # Should mention global variables as a risk factor
        assert any("Global" in rf or "global" in rf.lower() for rf in pred.risk_factors)

    def test_prediction_probability_capped(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        # Create an extremely complex file
        lines = ["GLOB = 1\n"] * 20
        lines.append("def monster():\n")
        for i in range(50):
            lines.append(f"    if x > {i}:\n        pass\n")
        lines.append("    return 0\n")
        for _ in range(500):
            lines.append("# filler\n")
        f = tmp_path / "extreme.py"
        f.write_text("".join(lines))
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None
        pred = BugPredictor().predict_file(ff)
        assert pred.probability <= 1.0

    def test_custom_thresholds(self, tmp_path: Path):
        from code_audit.ml.bug_predictor import BugPredictor
        from code_audit.ml.feature_extraction import extract_file_features

        f = tmp_path / "mod.py"
        f.write_text("x = 1\n")
        ff = extract_file_features(f, root=tmp_path)
        assert ff is not None

        # Strict thresholds → lower comment density threshold triggers penalty
        strict = BugPredictor(comment_density_threshold=0.99)
        pred = strict.predict_file(ff)
        # With threshold=0.99, almost any file will trigger low-comment penalty
        assert any("comment" in rf.lower() for rf in pred.risk_factors)


# ════════════════════════════════════════════════════════════════════
# Code Clustering
# ════════════════════════════════════════════════════════════════════


class TestCodeClustering:
    """Tests for ml.code_clustering module."""

    def _make_files(self, tmp_path: Path, count: int = 6) -> list[Path]:
        """Create a batch of Python files with varying complexity."""
        files = []
        for i in range(count):
            code_lines = [f"# File {i}\n"]
            for j in range(i * 5 + 1):
                code_lines.append(f"x_{j} = {j}\n")
            if i > 2:
                code_lines.append("def func():\n    pass\n")
            f = tmp_path / f"mod_{i}.py"
            f.write_text("".join(code_lines))
            files.append(f)
        return files

    def test_cluster_assigns_all_files(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer

        files = self._make_files(tmp_path)
        result = CodeClusterer(n_clusters=2).cluster(tmp_path, files)
        total_members = sum(len(c.members) for c in result.clusters)
        total = total_members + len(result.outliers)
        assert total == len(files)

    def test_cluster_auto_k(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer

        files = self._make_files(tmp_path, count=8)
        result = CodeClusterer(n_clusters="auto").cluster(tmp_path, files)
        assert len(result.clusters) >= 1
        assert result.inertia >= 0.0

    def test_cluster_from_features(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer
        from code_audit.ml.feature_extraction import extract_batch

        files = self._make_files(tmp_path, count=6)
        features = extract_batch(tmp_path, files)
        result = CodeClusterer(n_clusters=2).cluster_from_features(features)
        assert len(result.clusters) == 2

    def test_cluster_empty_input(self):
        from code_audit.ml.code_clustering import CodeClusterer

        result = CodeClusterer().cluster_from_features([])
        assert result.clusters == []
        assert result.outliers == []
        assert result.inertia == 0.0

    def test_cluster_single_file(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer

        (tmp_path / "only.py").write_text("x = 1\n")
        result = CodeClusterer(n_clusters=1).cluster(
            tmp_path, [tmp_path / "only.py"]
        )
        assert len(result.clusters) == 1

    def test_cluster_summary_output(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer

        files = self._make_files(tmp_path)
        result = CodeClusterer(n_clusters=2).cluster(tmp_path, files)
        summary = result.summary()
        assert "cluster" in summary.lower()

    def test_cluster_labels_assigned(self, tmp_path: Path):
        from code_audit.ml.code_clustering import CodeClusterer

        files = self._make_files(tmp_path, count=6)
        result = CodeClusterer(n_clusters=2).cluster(tmp_path, files)
        for c in result.clusters:
            # Label should be a non-empty string
            assert isinstance(c.label, str)

    def test_cluster_k_capped_at_n(self, tmp_path: Path):
        """Requesting more clusters than files should still work."""
        from code_audit.ml.code_clustering import CodeClusterer

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        result = CodeClusterer(n_clusters=10).cluster(
            tmp_path, [tmp_path / "a.py", tmp_path / "b.py"]
        )
        assert len(result.clusters) <= 2

    def test_euclidean_distance(self):
        from code_audit.ml.code_clustering import _euclidean

        assert _euclidean([0, 0], [3, 4]) == 5.0
        assert _euclidean([1, 1], [1, 1]) == 0.0

    def test_normalize(self):
        from code_audit.ml.code_clustering import _normalize

        vectors = [[0, 10], [5, 20], [10, 30]]
        normed, mins, maxs = _normalize(vectors)
        assert normed[0] == [0.0, 0.0]
        assert normed[2] == [1.0, 1.0]


# ════════════════════════════════════════════════════════════════════
# ML Package Init
# ════════════════════════════════════════════════════════════════════


class TestMLPackageInit:
    """Test that ml/__init__.py exports work."""

    def test_imports(self):
        from code_audit.ml import (
            extract_file_features,
            BugPredictor,
            CodeClusterer,
        )

        assert callable(extract_file_features)
        assert callable(BugPredictor)
        assert callable(CodeClusterer)


# ════════════════════════════════════════════════════════════════════
# Reports Package Init
# ════════════════════════════════════════════════════════════════════


class TestReportsPackageInit:
    """Test that reports/__init__.py exports work."""

    def test_imports(self):
        from code_audit.reports import (
            generate_debt_report,
            export_result,
            render_dashboard,
            compute_trend,
            load_trend_data,
        )

        assert callable(generate_debt_report)
        assert callable(export_result)
        assert callable(render_dashboard)
        assert callable(compute_trend)
        assert callable(load_trend_data)


# ════════════════════════════════════════════════════════════════════
# CLI Smoke Tests (Phase 7 subcommands)
# ════════════════════════════════════════════════════════════════════


class TestCLISmoke:
    """Smoke tests for new Phase 7 CLI subcommands."""

    def test_trend_no_registry(self):
        from code_audit.__main__ import main

        rc = main(["trend", "--registry-dir", "__nonexistent__"])
        assert rc == 2

    def test_trend_empty_registry(self, tmp_path: Path):
        from code_audit.__main__ import main

        reg = tmp_path / "snaps"
        reg.mkdir()
        rc = main(["trend", "--registry-dir", str(reg)])
        assert rc == 0

    def test_trend_json_format(self, tmp_path: Path):
        from code_audit.__main__ import main

        reg = tmp_path / "snaps"
        reg.mkdir()
        (reg / "s1.json").write_text(json.dumps({
            "name": "s1",
            "created_at": "2025-01-01",
            "debt_count": 3,
            "items": [{"debt_type": "todo"}] * 3,
        }))
        rc = main(["trend", "--registry-dir", str(reg), "--format", "json"])
        assert rc == 0

    def test_trend_output_file(self, tmp_path: Path):
        from code_audit.__main__ import main

        reg = tmp_path / "snaps"
        reg.mkdir()
        out = tmp_path / "trend.md"
        rc = main(["trend", "--registry-dir", str(reg), "--output", str(out)])
        assert rc == 0
        assert out.exists()

    def test_export_nonexistent_path(self):
        from code_audit.__main__ import main

        rc = main(["export", "__nonexistent__"])
        assert rc == 2

    def test_export_json(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        rc = main(["export", str(tmp_path), "--format", "json"])
        assert rc == 0

    def test_export_markdown(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        rc = main(["export", str(tmp_path), "--format", "markdown"])
        assert rc == 0

    def test_export_html_to_file(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        out = tmp_path / "report.html"
        rc = main(["export", str(tmp_path), "--format", "html", "--output", str(out)])
        assert rc == 0
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content

    def test_dashboard_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["dashboard", "__nonexistent__"])
        assert rc == 2

    def test_dashboard_basic(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        rc = main(["dashboard", str(tmp_path)])
        assert rc == 0

    def test_predict_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["predict", "__nonexistent__"])
        assert rc == 2

    def test_predict_basic(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        rc = main(["predict", str(tmp_path)])
        assert rc == 0

    def test_predict_json(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "x.py").write_text("x = 1\n")
        rc = main(["predict", str(tmp_path), "--json"])
        assert rc == 0

    def test_cluster_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["cluster", "__nonexistent__"])
        assert rc == 2

    def test_cluster_basic(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\ndef foo(): pass\n")
        rc = main(["cluster", str(tmp_path)])
        assert rc == 0

    def test_cluster_json(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        rc = main(["cluster", str(tmp_path), "--json"])
        assert rc == 0

    def test_cluster_explicit_k(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        rc = main(["cluster", str(tmp_path), "--k", "2"])
        assert rc == 0

    def test_cluster_invalid_k(self, tmp_path: Path):
        from code_audit.__main__ import main

        rc = main(["cluster", str(tmp_path), "--k", "abc"])
        assert rc == 2
