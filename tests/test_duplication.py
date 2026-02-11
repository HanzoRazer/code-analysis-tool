"""Tests for the DuplicationAnalyzer."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_audit.analyzers.duplication import DuplicationAnalyzer
from code_audit.model import AnalyzerType, Severity


class TestDuplicationAnalyzer:
    """Unit tests for the AST-based duplication detector."""

    def test_analyzer_protocol(self):
        """Analyzer has required id, version, run method."""
        analyzer = DuplicationAnalyzer()
        assert analyzer.id == "duplication"
        assert analyzer.version == "1.0.0"
        assert callable(analyzer.run)

    def test_no_clones_in_unique_code(self, tmp_path: Path):
        """Unique functions produce no findings."""
        code = textwrap.dedent("""\
            def alpha(x):
                return x + 1

            def beta(x):
                if x > 0:
                    return x * 2
                return 0

            def gamma(x, y):
                for i in range(x):
                    if i > y:
                        break
                return i
        """)
        (tmp_path / "unique.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=3)
        findings = analyzer.run(tmp_path, [tmp_path / "unique.py"])
        assert findings == []

    def test_detects_identical_functions(self, tmp_path: Path):
        """Two structurally identical functions are flagged as clones."""
        code = textwrap.dedent("""\
            def process_a(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result

            def process_b(values):
                output = []
                for val in values:
                    if val > 0:
                        output.append(val * 2)
                    else:
                        output.append(0)
                return output
        """)
        (tmp_path / "clones.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "clones.py"])

        assert len(findings) == 2  # one per clone in the group
        for f in findings:
            assert f.type == AnalyzerType.COMPLEXITY
            assert f.metadata["clone_count"] == 2
            assert "structural clone" in f.message

    def test_detects_clones_across_files(self, tmp_path: Path):
        """Clones in separate files are detected."""
        func_body = textwrap.dedent("""\
            def do_work(items):
                result = []
                for item in items:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result
        """)
        (tmp_path / "a.py").write_text(func_body)
        (tmp_path / "b.py").write_text(func_body.replace("do_work", "do_stuff"))

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "a.py", tmp_path / "b.py"])

        assert len(findings) == 2
        paths = {f.location.path for f in findings}
        assert "a.py" in paths
        assert "b.py" in paths

    def test_ignores_short_functions(self, tmp_path: Path):
        """Functions below min_lines are not considered."""
        code = textwrap.dedent("""\
            def short_a(x):
                return x + 1

            def short_b(y):
                return y + 1
        """)
        (tmp_path / "short.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "short.py"])
        assert findings == []

    def test_min_lines_configurable(self, tmp_path: Path):
        """Lower min_lines catches shorter clones."""
        code = textwrap.dedent("""\
            def calc_a(x):
                if x > 0:
                    return x * 2
                return 0

            def calc_b(y):
                if y > 0:
                    return y * 2
                return 0
        """)
        (tmp_path / "short_clones.py").write_text(code)

        # min_lines=6 → nothing
        analyzer_strict = DuplicationAnalyzer(min_lines=6)
        assert analyzer_strict.run(tmp_path, [tmp_path / "short_clones.py"]) == []

        # min_lines=3 → caught
        analyzer_loose = DuplicationAnalyzer(min_lines=3)
        findings = analyzer_loose.run(tmp_path, [tmp_path / "short_clones.py"])
        assert len(findings) == 2

    def test_three_clones_gives_medium_severity(self, tmp_path: Path):
        """Clone groups with ≥3 members get MEDIUM severity."""
        template = textwrap.dedent("""\
            def {name}(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result
        """)
        code = "\n".join(template.format(name=n) for n in ["f1", "f2", "f3"])
        (tmp_path / "triples.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "triples.py"])

        assert len(findings) == 3
        for f in findings:
            assert f.severity == Severity.MEDIUM
            assert f.metadata["rule_id"] == "DUP-GROUP-001"
            assert f.metadata["clone_count"] == 3

    def test_pair_clones_gives_low_severity(self, tmp_path: Path):
        """Clone groups with exactly 2 members get LOW severity."""
        code = textwrap.dedent("""\
            def worker_a(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result

            def worker_b(values):
                output = []
                for val in values:
                    if val > 0:
                        output.append(val * 2)
                    else:
                        output.append(0)
                return output
        """)
        (tmp_path / "pair.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "pair.py"])

        assert len(findings) == 2
        for f in findings:
            assert f.severity == Severity.LOW
            assert f.metadata["rule_id"] == "DUP-PAIR-001"

    def test_normalisation_ignores_names_and_literals(self, tmp_path: Path):
        """Functions differing only in variable names/literals are clones."""
        code = textwrap.dedent("""\
            def transform_users(users):
                output = []
                for user in users:
                    if user > 100:
                        output.append(user * 3)
                    else:
                        output.append(-1)
                return output

            def transform_orders(orders):
                results = []
                for order in orders:
                    if order > 999:
                        results.append(order * 7)
                    else:
                        results.append(-42)
                return results
        """)
        (tmp_path / "norm.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "norm.py"])
        assert len(findings) == 2  # same structure despite different names/constants

    def test_finding_id_prefix(self, tmp_path: Path):
        """Duplication findings have 'dup_' prefixed IDs."""
        code = textwrap.dedent("""\
            def proc_x(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item)
                    else:
                        result.append(0)
                return result

            def proc_y(items):
                out = []
                for i in items:
                    if i > 0:
                        out.append(i)
                    else:
                        out.append(0)
                return out
        """)
        (tmp_path / "ids.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "ids.py"])
        assert all(f.finding_id.startswith("dup_") for f in findings)

    def test_deterministic_fingerprints(self, tmp_path: Path):
        """Same code produces same fingerprints across runs."""
        code = textwrap.dedent("""\
            def fa(x):
                result = []
                for i in x:
                    if i > 0:
                        result.append(i)
                    else:
                        result.append(0)
                return result

            def fb(y):
                out = []
                for j in y:
                    if j > 0:
                        out.append(j)
                    else:
                        out.append(0)
                return out
        """)
        (tmp_path / "det.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        run1 = analyzer.run(tmp_path, [tmp_path / "det.py"])
        run2 = analyzer.run(tmp_path, [tmp_path / "det.py"])
        assert [f.fingerprint for f in run1] == [f.fingerprint for f in run2]

    def test_peer_locations_in_metadata(self, tmp_path: Path):
        """Each finding lists its peer locations."""
        template = textwrap.dedent("""\
            def {name}(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result
        """)
        code = template.format(name="clone_a") + "\n" + template.format(name="clone_b")
        (tmp_path / "peers.py").write_text(code)

        analyzer = DuplicationAnalyzer(min_lines=6)
        findings = analyzer.run(tmp_path, [tmp_path / "peers.py"])
        assert len(findings) == 2
        for f in findings:
            assert "peer_locations" in f.metadata
            assert len(f.metadata["peer_locations"]) == 1  # one peer each

    def test_syntax_error_files_skipped(self, tmp_path: Path):
        """Files with syntax errors are silently skipped."""
        (tmp_path / "bad.py").write_text("def oops(:\n    pass\n")
        analyzer = DuplicationAnalyzer(min_lines=3)
        findings = analyzer.run(tmp_path, [tmp_path / "bad.py"])
        assert findings == []

    # ── integration with pipeline ────────────────────────────────────

    def test_works_in_run_scan(self, tmp_path: Path):
        """DuplicationAnalyzer integrates with the scan pipeline."""
        from code_audit.core.runner import run_scan

        template = textwrap.dedent("""\
            def {name}(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                    else:
                        result.append(0)
                return result
        """)
        code = template.format(name="dup_a") + "\n" + template.format(name="dup_b")
        (tmp_path / "dupes.py").write_text(code)

        result = run_scan(tmp_path, [DuplicationAnalyzer(min_lines=6)])
        dup_findings = [
            f for f in result.findings
            if f.metadata.get("rule_id", "").startswith("DUP-")
        ]
        assert len(dup_findings) == 2
