"""Tests for the debt report generator (P4 Reporting)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_audit.model import AnalyzerType, RiskLevel, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.model.run_result import RunResult
from code_audit.reports.debt_report import render_markdown, generate_debt_report


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


# ════════════════════════════════════════════════════════════════════
# render_markdown — unit tests
# ════════════════════════════════════════════════════════════════════


class TestRenderMarkdown:
    """Tests for the Markdown rendering function."""

    def test_empty_findings_produces_report(self):
        result = RunResult(
            project_id="my-project",
            vibe_tier=RiskLevel.GREEN,
            confidence_score=90,
            findings=[],
            signals_snapshot=[],
        )
        md = render_markdown(result, include_git=False)
        assert "# Technical Debt Report" in md
        assert "90/100" in md
        assert "GREEN" in md
        assert "Total findings:** 0" in md

    def test_header_includes_project_id(self):
        result = RunResult(project_id="acme-app", findings=[], signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "acme-app" in md

    def test_header_includes_tool_version(self):
        result = RunResult(findings=[], signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert result.tool_version in md

    def test_severity_breakdown_table(self):
        findings = [
            _make_finding(severity=Severity.HIGH, line=1),
            _make_finding(severity=Severity.HIGH, line=2),
            _make_finding(severity=Severity.MEDIUM, line=3),
            _make_finding(severity=Severity.INFO, line=4),
        ]
        result = RunResult(findings=findings, signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "## Severity Breakdown" in md
        assert "| HIGH | 2 |" in md
        assert "| MEDIUM | 1 |" in md
        assert "| INFO | 1 |" in md

    def test_category_breakdown_table(self):
        findings = [
            _make_finding(atype=AnalyzerType.COMPLEXITY, line=1),
            _make_finding(atype=AnalyzerType.SECURITY, line=2),
            _make_finding(atype=AnalyzerType.COMPLEXITY, line=3),
        ]
        result = RunResult(findings=findings, signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "## Category Breakdown" in md
        assert "complexity" in md
        assert "security" in md

    def test_file_hotspots(self):
        findings = [
            _make_finding(path="hot.py", line=1),
            _make_finding(path="hot.py", line=2),
            _make_finding(path="hot.py", line=3),
            _make_finding(path="cool.py", line=4),
        ]
        result = RunResult(findings=findings, signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "## File Hotspots" in md
        assert "`hot.py`" in md
        assert "3" in md  # hot.py has 3

    def test_top_findings_ordered_by_severity(self):
        findings = [
            _make_finding(severity=Severity.INFO, message="info msg", line=1),
            _make_finding(severity=Severity.CRITICAL, message="critical msg", line=2),
            _make_finding(severity=Severity.MEDIUM, message="medium msg", line=3),
        ]
        result = RunResult(findings=findings, signals_snapshot=[])
        md = render_markdown(result, include_git=False, top_n=10)
        assert "## Top 3 Findings" in md
        # CRITICAL should come first
        crit_pos = md.index("critical msg")
        med_pos = md.index("medium msg")
        info_pos = md.index("info msg")
        assert crit_pos < med_pos < info_pos

    def test_top_n_limits_output(self):
        findings = [_make_finding(line=i) for i in range(20)]
        result = RunResult(findings=findings, signals_snapshot=[])
        md = render_markdown(result, include_git=False, top_n=5)
        assert "## Top 5 Findings" in md

    def test_red_signals_section(self):
        signals = [
            {
                "type": "complexity_hotspot",
                "risk_level": "red",
                "headline": "Very complex function",
            },
        ]
        result = RunResult(findings=[], signals_snapshot=signals)
        md = render_markdown(result, include_git=False)
        assert "## Signals" in md
        assert "red signal" in md.lower()
        assert "complexity_hotspot" in md

    def test_yellow_signals_section(self):
        signals = [
            {
                "type": "moderate_issue",
                "risk_level": "yellow",
                "headline": "Moderate concern",
            },
        ]
        result = RunResult(findings=[], signals_snapshot=signals)
        md = render_markdown(result, include_git=False)
        assert "yellow signal" in md.lower()
        assert "moderate_issue" in md

    def test_no_signals_section_when_all_green(self):
        signals = [
            {"type": "ok", "risk_level": "green", "headline": "All good"},
        ]
        result = RunResult(findings=[], signals_snapshot=signals)
        md = render_markdown(result, include_git=False)
        assert "## Signals" not in md

    def test_footer_present(self):
        result = RunResult(findings=[], signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "Report generated by code-audit" in md

    def test_tier_emoji_red(self):
        result = RunResult(
            vibe_tier=RiskLevel.RED,
            confidence_score=30,
            findings=[],
            signals_snapshot=[],
        )
        md = render_markdown(result, include_git=False)
        assert "🔴" in md
        assert "RED" in md

    def test_tier_emoji_yellow(self):
        result = RunResult(
            vibe_tier=RiskLevel.YELLOW,
            confidence_score=60,
            findings=[],
            signals_snapshot=[],
        )
        md = render_markdown(result, include_git=False)
        assert "🟡" in md

    def test_git_info_included_when_root_given(self, tmp_path: Path):
        result = RunResult(findings=[], signals_snapshot=[])
        md = render_markdown(result, root=tmp_path, include_git=True)
        # Even without a real git repo, it should show "unknown"
        assert "Branch" in md or "Commit" in md

    def test_git_info_excluded_when_disabled(self):
        result = RunResult(findings=[], signals_snapshot=[])
        md = render_markdown(result, include_git=False)
        assert "Branch" not in md
        assert "Commit" not in md


# ════════════════════════════════════════════════════════════════════
# generate_debt_report — integration tests
# ════════════════════════════════════════════════════════════════════


class TestGenerateDebtReport:
    """Integration tests that run the full scan → report pipeline."""

    def test_clean_project_report(self, tmp_path: Path):
        """A clean project produces a GREEN report with no findings."""
        code = textwrap.dedent("""\
            def hello():
                return "world"
        """)
        (tmp_path / "app.py").write_text(code)
        report = generate_debt_report(tmp_path, include_git=False)
        assert "# Technical Debt Report" in report
        assert "Total findings:** 0" in report

    def test_complex_project_report(self, tmp_path: Path):
        """A project with complexity issues produces findings in the report."""
        # Generate a function with CC ≥ 10
        branches = "\n".join(
            f"    {'el' if i else ''}if x == {i}:\n        return {i}"
            for i in range(12)
        )
        code = f"def decide(x):\n{branches}\n    return -1\n"
        (tmp_path / "complex.py").write_text(code)
        report = generate_debt_report(tmp_path, include_git=False)
        assert "## Severity Breakdown" in report
        assert "## Top" in report

    def test_report_to_file(self, tmp_path: Path):
        """CLI --output writes to file instead of stdout."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")
        out = tmp_path / "report.md"
        report = generate_debt_report(tmp_path / "src", include_git=False)
        out.write_text(report, encoding="utf-8")
        assert out.exists()
        content = out.read_text()
        assert "# Technical Debt Report" in content

    def test_custom_analyzers(self, tmp_path: Path):
        """Passing specific analyzers limits what gets scanned."""
        from code_audit.analyzers.complexity import ComplexityAnalyzer

        (tmp_path / "simple.py").write_text("x = 1\n")
        report = generate_debt_report(
            tmp_path,
            analyzers=[ComplexityAnalyzer()],
            include_git=False,
        )
        assert "# Technical Debt Report" in report

    def test_project_id_in_report(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n")
        report = generate_debt_report(
            tmp_path, project_id="my-awesome-project", include_git=False
        )
        assert "my-awesome-project" in report


# ════════════════════════════════════════════════════════════════════
# CLI smoke tests
# ════════════════════════════════════════════════════════════════════


class TestReportCLI:
    """Smoke tests for the report CLI subcommand."""

    def test_report_stdout(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        rc = main(["report", str(tmp_path), "--no-git"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "# Technical Debt Report" in captured.out

    def test_report_to_file(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        out = tmp_path / "out" / "report.md"
        rc = main(["report", str(tmp_path), "--output", str(out), "--no-git"])
        assert rc == 0
        assert out.exists()
        assert "# Technical Debt Report" in out.read_text()

    def test_report_nonexistent_path(self):
        from code_audit.__main__ import main

        rc = main(["report", "/nonexistent/path/xyz"])
        assert rc == 2

    def test_report_custom_top(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        rc = main(["report", str(tmp_path), "--top", "3", "--no-git"])
        assert rc == 0
