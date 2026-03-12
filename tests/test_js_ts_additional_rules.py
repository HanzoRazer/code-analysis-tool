"""Test: All four JS/TS security rules.

Phase 5 of Multi-Language Analyzer implementation.
Verifies:
1. all_rules.js triggers all 4 rules (eval, new Function, empty catch, globalThis).
2. negative.js triggers zero rules.
3. Each rule produces the correct metadata.
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

_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "repos" / "sample_repo_js_ts_all"


def test_all_rules_triggered():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    rule_ids = {f.metadata["rule_id"] for f in findings}

    assert "SEC_EVAL_JS_001" in rule_ids, f"Missing SEC_EVAL_JS_001 in {rule_ids}"
    assert "SEC_NEW_FUNCTION_JS_001" in rule_ids, f"Missing SEC_NEW_FUNCTION_JS_001 in {rule_ids}"
    assert "EXC_EMPTY_CATCH_JS_001" in rule_ids, f"Missing EXC_EMPTY_CATCH_JS_001 in {rule_ids}"
    assert "GST_GLOBAL_THIS_MUTATION_001" in rule_ids, f"Missing GST_GLOBAL_THIS_MUTATION_001 in {rule_ids}"
    assert "SEC_DYNAMIC_MODULE_LOAD_JS_001" in rule_ids, f"Missing SEC_DYNAMIC_MODULE_LOAD_JS_001 in {rule_ids}"


def test_all_rules_correct_count():
    """all_rules.js should produce exactly 5 findings (one per rule)."""
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    assert len(findings) == 5, f"Expected 5, got {len(findings)}: {[f.metadata['rule_id'] for f in findings]}"


def test_negative_file_produces_zero_findings():
    """negative.js should produce zero findings."""
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    neg_file = root / "web" / "negative.js"
    files_by_lang = {"py": [], "js": [neg_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    assert len(findings) == 0, f"Expected 0, got {len(findings)}: {[f.metadata['rule_id'] for f in findings]}"


def test_new_function_severity():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    nf = [f for f in findings if f.metadata["rule_id"] == "SEC_NEW_FUNCTION_JS_001"]
    assert len(nf) == 1
    assert nf[0].severity.value == "high"


def test_empty_catch_severity():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    ec = [f for f in findings if f.metadata["rule_id"] == "EXC_EMPTY_CATCH_JS_001"]
    assert len(ec) == 1
    assert ec[0].severity.value == "medium"


def test_global_this_mutation_severity():
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    gm = [f for f in findings if f.metadata["rule_id"] == "GST_GLOBAL_THIS_MUTATION_001"]
    assert len(gm) == 1
    assert gm[0].severity.value == "medium"


def test_dynamic_module_load_rule():
    """all_rules.js should trigger SEC_DYNAMIC_MODULE_LOAD_JS_001."""
    analyzer = JsTsSecurityPreviewAnalyzer()
    root = _FIXTURE_ROOT
    all_rules_file = root / "web" / "all_rules.js"
    files_by_lang = {"py": [], "js": [all_rules_file], "ts": []}

    findings = analyzer.run_multilang(root, files_by_lang)
    dml = [f for f in findings if f.metadata["rule_id"] == "SEC_DYNAMIC_MODULE_LOAD_JS_001"]
    assert len(dml) == 1, f"Expected 1 dynamic module load finding, got {len(dml)}"
    assert dml[0].severity.value == "high"


def test_dynamic_module_load_literal_is_safe(tmp_path: Path):
    """require('string-literal') should NOT trigger the rule."""
    js_file = tmp_path / "safe.js"
    js_file.write_text("const x = require('express');\n", encoding="utf-8")
    files_by_lang = {"py": [], "js": [js_file], "ts": []}

    analyzer = JsTsSecurityPreviewAnalyzer()
    findings = analyzer.run_multilang(tmp_path, files_by_lang)
    dml = [f for f in findings if f.metadata.get("rule_id") == "SEC_DYNAMIC_MODULE_LOAD_JS_001"]
    assert len(dml) == 0, f"Literal require should be safe, got: {dml}"
