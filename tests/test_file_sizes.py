"""Tests for file_sizes analyzer."""

import tempfile
from pathlib import Path

import pytest

from code_audit.analyzers.file_sizes import FileSizesAnalyzer, DEFAULT_EXTENSIONS
from code_audit.model import AnalyzerType, Severity


class TestFileSizesAnalyzer:
    """Unit tests for FileSizesAnalyzer."""

    def test_analyzer_protocol(self):
        """Analyzer has required id, version, run method."""
        analyzer = FileSizesAnalyzer()
        assert analyzer.id == "file_sizes"
        assert analyzer.version == "1.1.0"
        assert callable(analyzer.run)

    def test_small_file_no_finding(self, tmp_path: Path):
        """Files under threshold produce no findings."""
        small_file = tmp_path / "small.py"
        small_file.write_text("x = 1\n" * 100)  # 100 lines

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [small_file])

        assert findings == []

    def test_large_file_produces_finding(self, tmp_path: Path):
        """Files over threshold produce a finding."""
        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 600)  # 600 lines

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [large_file])

        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.COMPLEXITY
        assert f.severity == Severity.MEDIUM
        assert "600 lines" in f.message
        assert f.metadata["line_count"] == 600
        assert f.metadata["over_by"] == 100

    def test_high_severity_for_very_large_files(self, tmp_path: Path):
        """Files over high threshold get HIGH severity."""
        huge_file = tmp_path / "huge.py"
        huge_file.write_text("x = 1\n" * 900)  # 900 lines

        analyzer = FileSizesAnalyzer(threshold=500, high_threshold=800)
        findings = analyzer.run(tmp_path, [huge_file])

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["rule_id"] == "FS-HIGH-001"

    def test_unsupported_extensions_ignored(self, tmp_path: Path):
        """Files with unsupported extensions are skipped."""
        txt_file = tmp_path / "large.txt"
        txt_file.write_text("line\n" * 600)

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [txt_file])

        assert findings == []

    def test_javascript_files_supported(self, tmp_path: Path):
        """JavaScript files are analyzed by default."""
        js_file = tmp_path / "large.js"
        js_file.write_text("const x = 1;\n" * 600)

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [js_file])

        assert len(findings) == 1
        assert "600 lines" in findings[0].message

    def test_typescript_files_supported(self, tmp_path: Path):
        """TypeScript files are analyzed by default."""
        ts_file = tmp_path / "large.ts"
        ts_file.write_text("const x: number = 1;\n" * 600)

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [ts_file])

        assert len(findings) == 1

    def test_vue_files_supported(self, tmp_path: Path):
        """Vue SFC files are analyzed by default."""
        vue_file = tmp_path / "large.vue"
        vue_file.write_text("<template>\n" + "  <div></div>\n" * 598 + "</template>\n")

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [vue_file])

        assert len(findings) == 1

    def test_custom_extensions(self, tmp_path: Path):
        """Custom extensions can be specified."""
        md_file = tmp_path / "large.md"
        md_file.write_text("# heading\n" * 600)

        # .md not in default, but can be added
        analyzer = FileSizesAnalyzer(threshold=500, extensions=[".md"])
        findings = analyzer.run(tmp_path, [md_file])

        assert len(findings) == 1

    def test_default_extensions_comprehensive(self):
        """Default extensions cover common languages."""
        assert ".py" in DEFAULT_EXTENSIONS
        assert ".js" in DEFAULT_EXTENSIONS
        assert ".ts" in DEFAULT_EXTENSIONS
        assert ".tsx" in DEFAULT_EXTENSIONS
        assert ".vue" in DEFAULT_EXTENSIONS
        assert ".java" in DEFAULT_EXTENSIONS
        assert ".cs" in DEFAULT_EXTENSIONS
        assert ".go" in DEFAULT_EXTENSIONS
        assert ".rs" in DEFAULT_EXTENSIONS
        assert ".cpp" in DEFAULT_EXTENSIONS

    def test_finding_has_fingerprint(self, tmp_path: Path):
        """Findings have deterministic fingerprints."""
        large_file = tmp_path / "big.py"
        large_file.write_text("x = 1\n" * 600)

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [large_file])

        assert len(findings) == 1
        assert findings[0].fingerprint.startswith("sha256:")
        assert len(findings[0].fingerprint) > 20

    def test_finding_id_assigned(self, tmp_path: Path):
        """Finding IDs are assigned from fingerprint."""
        large_file = tmp_path / "big.py"
        large_file.write_text("x = 1\n" * 600)

        analyzer = FileSizesAnalyzer(threshold=500)
        findings = analyzer.run(tmp_path, [large_file])

        assert len(findings) == 1
        assert findings[0].finding_id.startswith("fs_")
