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


def test_v2_template_validates_against_schema():
    """A fill-in template that cannot validate teaches an invalid manifest."""
    import jsonschema

    schema = json.loads(
        (_REPO / "cbsp21" / "patch_input_v2.schema.json").read_text(encoding="utf-8")
    )
    template = json.loads(
        (_REPO / "cbsp21" / "patch_input_v2.template.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(template, schema)


# ── fail-loud on malformed / wrong-version manifests ────────────────


def _critical_kind(findings):
    assert len(findings) == 1, findings
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].metadata["rule_id"] == "PR_SCOPE_UNCHECKABLE_001"
    return findings[0].metadata["kind"]


def test_non_numeric_min_coverage_fails_loud_not_crash(tmp_path):
    m = _manifest(tmp_path, scope={"min_coverage_percent": "ninety-five"})
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    assert _critical_kind(f) == "malformed_manifest"


def test_non_object_scope_fails_loud_not_crash(tmp_path):
    m = tmp_path / "bad.json"
    m.write_text(
        json.dumps(
            {
                "schema_version": "cbsp21_patch_manifest_v2",
                "scope": ["src/"],
                "diff_range": {"base": "main"},
            }
        ),
        encoding="utf-8",
    )
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    assert _critical_kind(f) == "malformed_manifest"


def test_non_string_pinned_merge_base_fails_loud_not_crash(tmp_path):
    m = _manifest(tmp_path, diff_range={"pinned_merge_base": 12345})
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    assert _critical_kind(f) == "malformed_manifest"


def test_v1_manifest_rejected_rather_than_silently_downgraded(tmp_path):
    """A v1 manifest carries no pinned_merge_base — drift would silently no-op."""
    m = _manifest(tmp_path, schema_version="cbsp21_patch_manifest_v1")
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    assert _critical_kind(f) == "schema_version_mismatch"


def test_empty_declared_scope_fails_loud(tmp_path):
    m = _manifest(
        tmp_path,
        scope={"paths_in_scope": [], "files_expected_to_change": []},
    )
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    assert _critical_kind(f) == "empty_declared_scope"


# ── coverage threshold direction ────────────────────────────────────


def test_manifest_cannot_lower_the_95_percent_floor(tmp_path):
    """min_coverage_percent below the contract floor must not weaken the gate."""
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py"],
            "min_coverage_percent": 10,
        },
    )
    # 6/10 in scope = 60% — above the manifest's 10% but below the 95% floor.
    changed = [f"src/f{i}.py" for i in range(6)] + [f"docs/d{i}.md" for i in range(4)]
    f = _run(tmp_path, manifest=m, changed=changed)
    cov = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_COVERAGE_001"]
    assert len(cov) == 1
    assert cov[0].metadata["threshold_percent"] == 95.0
    assert cov[0].metadata["triggered_by"] == ["scope_coverage"]


def test_manifest_may_raise_the_floor(tmp_path):
    m = _manifest(
        tmp_path,
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/a.py"],
            "min_coverage_percent": 100,
        },
    )
    # 99/100 in scope = 99% — clean at 95%, a finding at the declared 100%.
    changed = [f"src/f{i}.py" for i in range(99)] + ["docs/d.md"]
    f = _run(tmp_path, manifest=m, changed=changed)
    cov = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_COVERAGE_001"]
    assert len(cov) == 1
    assert cov[0].metadata["threshold_percent"] == 100.0


def test_coverage_message_names_the_metric_that_tripped(tmp_path):
    """Scope coverage is clean; only the declared file-context figure is low."""
    m = _manifest(
        tmp_path,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
        file_context_coverage_percent=40.0,
    )
    f = _run(tmp_path, manifest=m, changed=["src/a.py"])
    cov = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_COVERAGE_001"]
    assert len(cov) == 1
    assert cov[0].metadata["triggered_by"] == ["file_context_coverage"]
    assert "file_context_coverage_percent" in cov[0].message
    assert "in-scope changed" not in cov[0].message


def test_coverage_fingerprint_is_stable_across_percentages(tmp_path):
    """Volatile numbers must not mint a new finding identity each run."""
    m = _manifest(
        tmp_path,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
    )
    a = _run(tmp_path, manifest=m, changed=["src/a.py", "docs/x.md"])
    b = _run(tmp_path, manifest=m, changed=["src/a.py", "docs/x.md", "docs/y.md"])
    fp_a = next(
        x.fingerprint for x in a if x.metadata["rule_id"] == "PR_SCOPE_COVERAGE_001"
    )
    fp_b = next(
        x.fingerprint for x in b if x.metadata["rule_id"] == "PR_SCOPE_COVERAGE_001"
    )
    assert fp_a == fp_b


# ── real git surface (previously exercised only via injection hooks) ─


def _git(repo: Path, *args: str) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout.strip()


def _repo_with_branch(tmp_path: Path, extra_files: list[str]) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    _git(repo.parent, "init", "-q", repo.name)
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "-qb", "feature")
    for rel in extra_files:
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "feature")
    return repo, base_sha


def test_real_git_diff_detects_contamination(tmp_path):
    repo, base_sha = _repo_with_branch(tmp_path, ["src/a.py", "docs/leak.md"])
    m = _manifest(
        repo,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
        diff_range={"base": base_sha, "head": "HEAD"},
    )
    f = PrScopeAnalyzer(review_context=ReviewContext(manifest_path=m)).run(repo, [])
    contamination = [
        x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_CONTAMINATION_001"
    ]
    assert [x.location.path for x in contamination] == ["docs/leak.md"]


def test_real_git_diff_handles_non_ascii_paths(tmp_path):
    """Without `-z`, git quotes non-ASCII names and a declared file reads as contamination."""
    repo, base_sha = _repo_with_branch(tmp_path, ["src/café.py"])
    m = _manifest(
        repo,
        scope={
            "paths_in_scope": ["src/"],
            "files_expected_to_change": ["src/café.py"],
        },
        diff_range={"base": base_sha, "head": "HEAD"},
    )
    f = PrScopeAnalyzer(review_context=ReviewContext(manifest_path=m)).run(repo, [])
    assert f == [], [x.message for x in f]


def test_real_git_base_drift_against_true_merge_base(tmp_path):
    repo, base_sha = _repo_with_branch(tmp_path, ["src/a.py"])
    m = _manifest(
        repo,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
        diff_range={"base": base_sha, "head": "HEAD", "pinned_merge_base": "d" * 40},
    )
    f = PrScopeAnalyzer(review_context=ReviewContext(manifest_path=m)).run(repo, [])
    drift = [x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_BASE_DRIFT_001"]
    assert len(drift) == 1
    assert drift[0].metadata["actual_merge_base"] == base_sha


def test_real_git_clean_scope_is_silent(tmp_path):
    repo, base_sha = _repo_with_branch(tmp_path, ["src/a.py"])
    m = _manifest(
        repo,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
        diff_range={"base": base_sha, "head": "HEAD", "pinned_merge_base": base_sha},
    )
    f = PrScopeAnalyzer(review_context=ReviewContext(manifest_path=m)).run(repo, [])
    assert f == [], [x.message for x in f]


def test_missing_base_with_pinned_merge_base_does_not_silently_pass(tmp_path):
    """`base` absent must not degrade to `merge-base HEAD HEAD` (empty diff)."""
    repo, base_sha = _repo_with_branch(tmp_path, ["src/a.py", "docs/leak.md"])
    m = _manifest(
        repo,
        scope={"paths_in_scope": ["src/"], "files_expected_to_change": ["src/a.py"]},
        diff_range={"head": "HEAD", "pinned_merge_base": base_sha},
    )
    data = json.loads(m.read_text(encoding="utf-8"))
    data["diff_range"].pop("base", None)
    m.write_text(json.dumps(data), encoding="utf-8")

    f = PrScopeAnalyzer(review_context=ReviewContext(manifest_path=m)).run(repo, [])
    assert f != []
    contamination = [
        x for x in f if x.metadata.get("rule_id") == "PR_SCOPE_CONTAMINATION_001"
    ]
    assert [x.location.path for x in contamination] == ["docs/leak.md"]
