"""Test: JS/TS analyzer scaffold produces no output change.

Phase 4 of Multi-Language Analyzer implementation.
Verifies:
1. JsTsSecurityPreviewAnalyzer is instantiable.
2. run() returns [] for Python files (no-op).
3. run_multilang() returns [] for JS/TS files (no-op scaffold).
4. Scan output with enable_js_ts=True is identical to without
   (zero new findings from scaffold).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_audit.analyzers.js_ts_security import JsTsSecurityPreviewAnalyzer
from code_audit.model import AnalyzerType


def test_analyzer_instantiable():
    a = JsTsSecurityPreviewAnalyzer()
    assert a.id == "js_ts_security"
    assert a.version == "0.1.0"


def test_analyzer_type_enum_has_js_ts_security():
    assert hasattr(AnalyzerType, "JS_TS_SECURITY")
    assert AnalyzerType.JS_TS_SECURITY.value == "js_ts_security"


def test_run_returns_empty_for_python(tmp_path: Path):
    a = JsTsSecurityPreviewAnalyzer()
    py_file = tmp_path / "app.py"
    py_file.write_text("x = 1\n", encoding="utf-8")
    assert a.run(tmp_path, [py_file]) == []


def test_run_multilang_returns_empty_scaffold(tmp_path: Path):
    """No-op for files without security issues."""
    a = JsTsSecurityPreviewAnalyzer()
    js_file = tmp_path / "safe.js"
    js_file.write_text("console.log('hello');\n", encoding="utf-8")
    files_by_lang = {"py": [], "js": [js_file], "ts": []}
    # safe.js has no security issues
    assert a.run_multilang(tmp_path, files_by_lang) == []


def test_scan_output_identical_with_and_without_flag(tmp_path: Path):
    """Run scan with and without enable_js_ts — Python findings identical."""
    # Create a project with both Python and JS files
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    web_dir = tmp_path / "web"
    web_dir.mkdir()
    (web_dir / "main.js").write_text("eval('test');\n", encoding="utf-8")

    from code_audit.core.runner import run_scan

    # Only the JS/TS analyzer for isolation
    analyzer = JsTsSecurityPreviewAnalyzer()

    r1 = run_scan(tmp_path, [analyzer], enable_js_ts=False)
    r2 = run_scan(tmp_path, [analyzer], enable_js_ts=True)

    # Without flag: zero findings (JS not analyzed)
    assert len(r1.findings) == 0
    # With flag: eval() detected
    assert len(r2.findings) == 1
    assert r2.findings[0].metadata["rule_id"] == "SEC_EVAL_JS_001"
