"""Test: SEC_EVAL_JS_001 eval() detection.

Phase 5 of Multi-Language Analyzer implementation.
Verifies:
1. eval() calls in JS files produce findings.
2. Safe JS files produce no findings.
3. Findings have correct rule_id, severity, location.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_audit.analyzers.js_ts_security import JsTsSecurityPreviewAnalyzer
from code_audit.parsers.tree_sitter_loader import is_available

pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="tree-sitter not installed",
)

_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "repos" / "sample_repo_js_ts_eval"


def test_eval_detected_in_main_js():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    js_files = sorted(root.rglob("*.js"))
    files_by_lang = {"py": [], "js": js_files, "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)

    # main.js has 2 eval() calls
    eval_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_EVAL_JS_001"]
    assert len(eval_findings) == 2, f"Expected 2 eval findings, got {len(eval_findings)}: {eval_findings}"


def test_eval_finding_has_correct_metadata():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    js_files = sorted(root.rglob("*.js"))
    files_by_lang = {"py": [], "js": js_files, "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    eval_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_EVAL_JS_001"]

    for f in eval_findings:
        assert f.severity.value == "high"
        assert f.type.value == "js_ts_security"
        assert f.confidence == 0.95
        assert "eval" in f.message.lower()
        assert f.metadata["language"] == "js"


def test_safe_js_produces_no_findings():
    """safe.js has no eval — should produce zero findings."""
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    safe_file = root / "web" / "safe.js"
    files_by_lang = {"py": [], "js": [safe_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    assert len(findings) == 0
