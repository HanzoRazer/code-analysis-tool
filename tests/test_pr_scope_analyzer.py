"""Acceptance tests for the pr_scope detector (locked contract).

Contract source: cbsp21/pr_scope_acceptance.json
"""
from __future__ import annotations

import json
from pathlib import Path

from code_audit.analyzers.pr_scope import PrScopeAnalyzer, ReviewContext
from code_audit.model import AnalyzerType, Severity

_REPO = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path, **overrides) -> Path:
    data = {
        "schema_version": "cbsp21_patch_manifest_v2",
        "patch_id": "T",
        "title": "t",
        "intent": "t",
        "change_type": "code",
        "behavior_change": "compatible",
        "risk_level": "low",
        "scope": {
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py"],
            "min_coverage_percent": 95,
        },
        "diff_range": {"base": "main", "head": "HEAD"},
        "changed_files_count": 1,
        "diff_articulation": {
            "what_changed": ["a"],
            "why_not_redundant": "b",
        },
        "verification": {"commands_run": ["true"]},
        "file_context_coverage_percent": 100.0,
    }
    # shallow merge overrides
    for k, v in overrides.items():
        if k == "scope":
            data["scope"] = {**data["scope"], **v}
        elif k == "diff_range":
            data["diff_range"] = {**data["diff_range"], **v}
        else:
            data[k] = v
    path = tmp_path / "patch_input.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _run(
    tmp_path: Path,
    *,
    manifest: Path,
    changed: list[str],
    actual_mb: str = "a" * 40,
):
    ctx = ReviewContext(
        manifest_path=manifest,
        changed_files=changed,
        actual_merge_base=actual_mb,
    )
    return PrScopeAnalyzer(review_context=ctx).run(tmp_path, [])


def test_ordinary_scan_without_review_context_is_silent(tmp_path):
    assert PrScopeAnalyzer().run(tmp_path, []) == []


def test_declared_changed_file_passes(tmp_path):
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py", "tests/test_a.py"],
        },
    )
    f = _run(tmp_path, manifest=m, changed=["src/a.py", "tests/test_a.py"])
    assert f == []


def test_undeclared_changed_file_contamination(tmp_path):
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/code_audit/"],
            "files_expected_to_change": ["src/code_audit/a.py"],
        },
    )
    f = _run(
        tmp_path,
        manifest=m,
        changed=["src/code_audit/a.py", "docs/SECRET.md"],
    )
    contamination = [
        x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_CONTAMINATION_001"
    ]
    assert len(contamination) == 1
    assert contamination[0].type is AnalyzerType.PR_SCOPE
    assert contamination[0].severity is Severity.MEDIUM
    assert contamination[0].location.path == "docs/SECRET.md"
    # 1/2 in-scope also trips the coverage summary — expected, not the focus here.


def test_pinned_base_drift(tmp_path):
    pinned = "b" * 40
    actual = "c" * 40
    m = _manifest(
        tmp_path,
        diff_range={"base": "main", "head": "HEAD", "pinned_merge_base": pinned},
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py"],
        },
    )
    f = _run(tmp_path, manifest=m, changed=["src/a.py"], actual_mb=actual)
    drift = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_BASE_DRIFT_001"]
    assert len(drift) == 1
    assert drift[0].severity is Severity.HIGH


def test_coverage_below_95_high_severity(tmp_path):
    # 1 of 20 changed files in scope → 5% coverage
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py"],
            "min_coverage_percent": 95,
        },
    )
    changed = ["src/a.py"] + [f"other/{i}.txt" for i in range(19)]
    f = _run(tmp_path, manifest=m, changed=changed)
    cov = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_COVERAGE_001"]
    assert len(cov) == 1
    assert cov[0].severity is Severity.HIGH
    assert cov[0].metadata["coverage_percent"] == 5.0


def test_clean_scope_zero_findings(tmp_path):
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/", "tests/"],
            "files_expected_to_change": ["src/a.py"],
        },
        file_context_coverage_percent=100.0,
    )
    assert _run(tmp_path, manifest=m, changed=["src/a.py"]) == []


def test_missing_manifest_fail_loud(tmp_path):
    ctx = ReviewContext(
        manifest_path=tmp_path / "does-not-exist.json",
        changed_files=["src/a.py"],
        actual_merge_base="a" * 40,
    )
    f = PrScopeAnalyzer(review_context=ctx).run(tmp_path, [])
    assert len(f) == 1
    assert f[0].severity is Severity.CRITICAL
    assert f[0].metadata["kind"] == "missing_manifest"


def test_unresolved_merge_base_fail_loud(tmp_path):
    """When git cannot resolve merge-base and no overrides — fail loud."""
    m = _manifest(tmp_path)
    # tmp_path is not a git repo; no overrides → uncheckable.
    ctx = ReviewContext(manifest_path=m)
    f = PrScopeAnalyzer(review_context=ctx).run(tmp_path, [])
    assert len(f) == 1
    assert f[0].severity is Severity.CRITICAL
    assert f[0].metadata["rule_id"] == "PR_SCOPE_UNCHECKABLE_001"
    assert f[0].metadata["kind"] in {
        "unresolved_merge_base",
        "git_diff_failed",
        "shallow_clone",
    }


def test_path_prefix_declares_scope(tmp_path):
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/code_audit/analyzers/"],
            "files_expected_to_change": ["src/code_audit/analyzers/pr_scope.py"],
        },
    )
    f = _run(
        tmp_path,
        manifest=m,
        changed=[
            "src/code_audit/analyzers/pr_scope.py",
            "src/code_audit/analyzers/other.py",
        ],
    )
    assert f == []


def test_acceptance_contract_file_lists_required_behaviors():
    path = _REPO / "cbsp21" / "pr_scope_acceptance.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    ids = {a["id"] for a in data["acceptance"]}
    assert {
        "declared_changed_passes",
        "undeclared_changed_contamination",
        "pinned_base_drift",
        "coverage_below_95",
        "clean_scope_zero_findings",
        "ordinary_scan_silent",
        "fail_loud_on_uncheckable",
    } <= ids


def test_v2_schema_example_validates_against_schema():
    import jsonschema

    schema = json.loads(
        (_REPO / "cbsp21" / "patch_input_v2.schema.json").read_text(encoding="utf-8")
    )
    example = json.loads(
        (_REPO / "cbsp21" / "patch_input_v2.example.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(example, schema)
