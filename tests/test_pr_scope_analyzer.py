"""Acceptance tests for the pr_scope detector.

Contract source: cbsp21/pr_scope_acceptance.json

The behaviour tests drive real Git repositories rather than injected diffs:
the detector's whole value is that it reads the true Git surface, so a test
that hands it a synthetic changed-file list proves very little.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from code_audit import check_pr_scope
from code_audit.__main__ import main
from code_audit.analyzers import pr_scope as pr_scope_module
from code_audit.analyzers.pr_scope import PrScopeAnalyzer, ReviewContext
from code_audit.contracts.validate import validate_finding
from code_audit.model import AnalyzerType, Severity
from code_audit.utils.exit_codes import ExitCode

_REPO = Path(__file__).resolve().parents[1]


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout.strip()


def _commit_file(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(root, "add", "--", name)
    _git(root, "commit", "-m", f"add {name}")


@pytest.fixture
def git_repo(tmp_path: Path) -> tuple[Path, str]:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "scope@example.test")
    _git(tmp_path, "config", "user.name", "Scope Test")
    _commit_file(tmp_path, "a.py", "a = 1\n")
    base = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    return tmp_path, base


def _write_manifest(
    root: Path,
    base: str,
    declared: list[str],
    *,
    base_ref: str | None = None,
    head: str = "HEAD",
    observed: list[str] | None = None,
    observed_count: int | None = None,
    head_sha: str | None = None,
    paths_in_scope: list[str] | None = None,
    min_coverage_percent: int | None = None,
    file_context_coverage_percent: float | None = None,
    base_sha_field: str = "base_sha",
    schema_version: str = "cbsp21_patch_manifest_v2",
    omit_base_sha: bool = False,
) -> Path:
    diff_range: dict = {"base": base_ref or base, "head": head}
    if not omit_base_sha:
        diff_range[base_sha_field] = base
    if head_sha is not None:
        diff_range["head_sha"] = head_sha

    scope: dict = {"files_expected_to_change": declared}
    if paths_in_scope is not None:
        scope["paths_in_scope"] = paths_in_scope
    if min_coverage_percent is not None:
        scope["min_coverage_percent"] = min_coverage_percent

    manifest: dict = {
        "schema_version": schema_version,
        "scope": scope,
        "diff_range": diff_range,
    }
    if observed is not None:
        manifest["changed_files_exact"] = observed
    if observed_count is not None:
        manifest["changed_files_count"] = observed_count
    if file_context_coverage_percent is not None:
        manifest["file_context_coverage_percent"] = file_context_coverage_percent

    path = root / "patch.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _rules(findings) -> set[str]:
    return {finding.metadata["rule_id"] for finding in findings}


# ── silence / clean pass ────────────────────────────────────────────


def test_no_context_is_silent(tmp_path: Path):
    assert PrScopeAnalyzer().run(tmp_path, []) == []


def test_clean_exact_scope_passes(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, ["b.py"], observed=["b.py"], observed_count=1)

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_empty_diff_is_clean(git_repo):
    root, base = git_repo
    manifest = _write_manifest(root, base, ["future.py"])

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_review_context_activation_matches_manifest_activation(git_repo):
    """scan_project's ReviewContext path and the gate path agree."""
    root, base = git_repo
    _commit_file(root, "leak.py", "leak = True\n")
    manifest = _write_manifest(root, base, ["intended.py"])

    via_manifest = PrScopeAnalyzer(manifest=manifest).run(root, [])
    via_context = PrScopeAnalyzer(
        review_context=ReviewContext(manifest_path=manifest)
    ).run(root, [])

    assert _rules(via_manifest) == _rules(via_context)
    assert via_manifest


def test_review_context_and_manifest_are_mutually_exclusive(tmp_path):
    with pytest.raises(ValueError):
        PrScopeAnalyzer(
            review_context=ReviewContext(manifest_path=tmp_path / "m.json"),
            manifest=tmp_path / "m.json",
        )


# ── contamination / scope declaration ───────────────────────────────


def test_contamination_emits_contract_valid_rule_metadata(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    _commit_file(root, "c.py", "c = 3\n")
    manifest = _write_manifest(root, base, ["b.py"])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])

    assert "pr_scope.undeclared_file" in _rules(findings)
    assert "pr_scope.coverage_below_threshold" in _rules(findings)
    assert any(f.location.path == "c.py" for f in findings)
    assert all(f.type is AnalyzerType.PR_SCOPE for f in findings)
    assert all(f.location.line_start == 1 for f in findings)
    for finding in findings:
        validate_finding(finding.to_dict())


def test_glob_declares_matching_files(git_repo):
    root, base = git_repo
    _commit_file(root, "tests/fixtures/expected/a.json", "{}\n")
    manifest = _write_manifest(root, base, ["tests/fixtures/expected/*.json"])

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_paths_in_scope_prefix_declares_directory(git_repo):
    root, base = git_repo
    _commit_file(root, "src/code_audit/analyzers/x.py", "x = 1\n")
    _commit_file(root, "src/code_audit/analyzers/y.py", "y = 2\n")
    manifest = _write_manifest(
        root, base, ["src/code_audit/analyzers/x.py"],
        paths_in_scope=["src/code_audit/analyzers/"],
    )

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_paths_in_scope_prefix_does_not_leak_to_sibling_dirs(git_repo):
    root, base = git_repo
    _commit_file(root, "src/code_audit_extra/z.py", "z = 1\n")
    manifest = _write_manifest(
        root, base, ["unused.py"], paths_in_scope=["src/code_audit/"]
    )

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])

    assert "pr_scope.undeclared_file" in _rules(findings)


def test_rename_and_path_with_spaces_use_new_git_path(git_repo):
    root, base = git_repo
    _git(root, "mv", "a.py", "renamed file.py")
    _git(root, "commit", "-m", "rename file")
    manifest = _write_manifest(root, base, ["renamed file.py"])

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_non_ascii_paths_are_not_mangled(git_repo):
    """Without -z, core.quotePath escapes the name and it reads as undeclared."""
    root, base = git_repo
    _commit_file(root, "src/café.py", "x = 1\n")
    manifest = _write_manifest(root, base, ["src/café.py"])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    assert findings == [], [f.message for f in findings]


# ── observed-file cross-checks ──────────────────────────────────────


def test_observed_files_and_count_are_cross_checked_not_authorized(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    _commit_file(root, "c.py", "c = 3\n")
    manifest = _write_manifest(
        root, base, ["b.py"], observed=["b.py"], observed_count=1
    )

    rules = _rules(PrScopeAnalyzer(manifest=manifest, base=base).run(root, []))

    assert "pr_scope.observed_files_mismatch" in rules
    assert "pr_scope.observed_count_mismatch" in rules
    assert "pr_scope.undeclared_file" in rules


# ── coverage threshold ──────────────────────────────────────────────


def test_coverage_threshold_boundary_is_medium(git_repo):
    root, base = git_repo
    declared = []
    for index in range(20):
        name = f"files/{index:02}.py"
        _commit_file(root, name, f"value = {index}\n")
        if index < 19:
            declared.append(name)
    manifest = _write_manifest(root, base, declared)

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    summary = next(
        f
        for f in findings
        if f.metadata["rule_id"] == "pr_scope.coverage_below_threshold"
    )

    assert summary.metadata["declared_coverage"] == 0.95
    assert summary.severity is Severity.MEDIUM


def test_manifest_cannot_lower_the_contract_floor(git_repo):
    """min_coverage_percent below the floor must not weaken the gate."""
    root, base = git_repo
    declared = []
    for index in range(10):
        name = f"files/{index:02}.py"
        _commit_file(root, name, f"value = {index}\n")
        if index < 6:
            declared.append(name)
    # 6/10 in scope = 60%; a manifest asking for 10 must not make that pass.
    manifest = _write_manifest(root, base, declared, min_coverage_percent=10)

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    summary = next(
        f for f in findings
        if f.metadata["rule_id"] == "pr_scope.coverage_below_threshold"
    )

    assert summary.metadata["coverage_threshold"] == 0.95
    assert summary.severity is Severity.HIGH


def test_manifest_may_raise_the_floor(git_repo):
    root, base = git_repo
    declared = []
    for index in range(20):
        name = f"files/{index:02}.py"
        _commit_file(root, name, f"value = {index}\n")
        if index < 19:
            declared.append(name)
    # 95% coverage: MEDIUM at the default floor, HIGH once the manifest asks 100.
    manifest = _write_manifest(root, base, declared, min_coverage_percent=100)

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    summary = next(
        f for f in findings
        if f.metadata["rule_id"] == "pr_scope.coverage_below_threshold"
    )

    assert summary.metadata["coverage_threshold"] == 1.0
    assert summary.severity is Severity.HIGH


def test_low_file_context_coverage_trips_the_summary(git_repo):
    """Scope coverage is clean; only the declared review-depth figure is low."""
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(
        root, base, ["b.py"], file_context_coverage_percent=40.0
    )

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    summary = next(
        f for f in findings
        if f.metadata["rule_id"] == "pr_scope.coverage_below_threshold"
    )

    assert summary.metadata["triggered_by"] == ["file_context_coverage"]
    assert "file_context_coverage_percent" in summary.message
    assert summary.severity is Severity.HIGH


def test_coverage_fingerprint_is_stable_across_percentages(git_repo):
    """Volatile numbers must not mint a new finding identity each run."""
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, ["declared.py"])
    first = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])

    _commit_file(root, "c.py", "c = 3\n")
    second = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])

    def summary_fp(findings):
        return next(
            f.fingerprint for f in findings
            if f.metadata["rule_id"] == "pr_scope.coverage_below_threshold"
        )

    assert summary_fp(first) == summary_fp(second)


# ── base / head pinning ─────────────────────────────────────────────


def test_base_drift_uses_full_resolved_commits(tmp_path: Path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "scope@example.test")
    _git(tmp_path, "config", "user.name", "Scope Test")
    _commit_file(tmp_path, "a.py", "a = 1\n")
    old_base = _git(tmp_path, "rev-parse", "HEAD")
    _commit_file(tmp_path, "base.py", "base = 2\n")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    _commit_file(tmp_path, "feature.py", "feature = 3\n")
    manifest = _write_manifest(tmp_path, old_base, ["feature.py"], base_ref="main")

    findings = PrScopeAnalyzer(manifest=manifest).run(tmp_path, [])

    assert "pr_scope.base_drift" in _rules(findings)


def test_pinned_merge_base_alias_is_accepted(git_repo):
    """Manifests written against the earlier v2 draft still work."""
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(
        root, base, ["b.py"], base_sha_field="pinned_merge_base"
    )

    assert PrScopeAnalyzer(manifest=manifest, base=base).run(root, []) == []


def test_optional_head_pin_detects_drift(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, ["b.py"], head_sha=base)

    assert "pr_scope.head_drift" in _rules(PrScopeAnalyzer(manifest=manifest).run(root, []))


def test_missing_base_pin_fails_loud(git_repo):
    """An unpinned base means drift detection would silently never run."""
    root, base = git_repo
    manifest = _write_manifest(root, base, ["b.py"], omit_base_sha=True)

    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])

    assert _rules(findings) == {"pr_scope.base_pin_missing"}
    assert findings[0].severity is Severity.CRITICAL


# ── fail-loud on unusable manifests / git ───────────────────────────


def test_empty_declared_scope_fails_loud(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, [])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])

    assert _rules(findings) == {"pr_scope.no_declared_files"}
    assert findings[0].severity is Severity.CRITICAL


def test_v1_manifest_rejected_rather_than_silently_downgraded(git_repo):
    root, base = git_repo
    manifest = _write_manifest(
        root, base, ["b.py"], schema_version="cbsp21_patch_manifest_v1"
    )

    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])

    assert _rules(findings) == {"pr_scope.schema_version_mismatch"}
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("manifest_text", "expected_rule"),
    [
        ("not json", "pr_scope.manifest_missing"),
        (json.dumps([]), "pr_scope.manifest_invalid"),
        (
            json.dumps({"schema_version": "cbsp21_patch_manifest_v2",
                        "scope": {}, "diff_range": {}}),
            "pr_scope.manifest_invalid",
        ),
        (
            json.dumps({"schema_version": "cbsp21_patch_manifest_v2",
                        "scope": ["src/"], "diff_range": {"base": "main"}}),
            "pr_scope.manifest_invalid",
        ),
    ],
)
def test_malformed_manifests_fail_loud(git_repo, manifest_text, expected_rule):
    root, _ = git_repo
    manifest = root / "patch.json"
    manifest.write_text(manifest_text, encoding="utf-8")

    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])
    assert _rules(findings) == {expected_rule}
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_non_numeric_min_coverage_fails_loud_not_crash(git_repo):
    root, base = git_repo
    manifest = _write_manifest(root, base, ["b.py"])
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["scope"]["min_coverage_percent"] = "ninety-five"
    manifest.write_text(json.dumps(data), encoding="utf-8")

    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])
    assert _rules(findings) == {"pr_scope.manifest_invalid"}


def test_unsafe_declared_path_is_rejected(git_repo):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, ["../b.py"])

    assert "pr_scope.manifest_invalid" in _rules(PrScopeAnalyzer(manifest=manifest).run(root, []))


def test_unresolvable_base_fails_loud(git_repo):
    root, base = git_repo
    manifest = _write_manifest(root, base, ["b.py"], base_ref="does-not-exist")

    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])
    assert "pr_scope.base_unresolved" in _rules(findings)
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_missing_git_executable_becomes_finding(git_repo, monkeypatch):
    root, base = git_repo
    manifest = _write_manifest(root, base, ["b.py"])

    def missing_git(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(pr_scope_module.subprocess, "run", missing_git)
    findings = PrScopeAnalyzer(manifest=manifest).run(root, [])

    assert _rules(findings) == {"pr_scope.git_unavailable"}


def test_git_timeout_becomes_finding(git_repo, monkeypatch):
    root, base = git_repo
    manifest = _write_manifest(root, base, ["b.py"])

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=0.01)

    monkeypatch.setattr(pr_scope_module.subprocess, "run", timeout)
    findings = PrScopeAnalyzer(manifest=manifest, git_timeout=0.01).run(root, [])

    assert _rules(findings) == {"pr_scope.git_timeout"}


# ── API / CLI parity ────────────────────────────────────────────────


def test_api_and_cli_share_gate_behavior(git_repo, capsys):
    root, base = git_repo
    _commit_file(root, "leak.py", "leak = True\n")
    manifest = _write_manifest(root, base, ["intended.py"])

    api_findings = check_pr_scope(root, manifest=manifest, base=base)
    rc = main([
        "pr-scope", "--root", str(root), "--manifest", str(manifest),
        "--base", base, "--json",
    ])
    output = json.loads(capsys.readouterr().out)

    assert api_findings
    assert rc == ExitCode.VIOLATION
    assert output["passed"] is False
    assert output["finding_count"] == len(api_findings)


def test_cli_clean_scope_exits_success(git_repo, capsys):
    root, base = git_repo
    _commit_file(root, "b.py", "b = 2\n")
    manifest = _write_manifest(root, base, ["b.py"])

    rc = main([
        "pr-scope", "--root", str(root), "--manifest", str(manifest),
        "--base", base, "--json",
    ])
    output = json.loads(capsys.readouterr().out)

    assert rc == ExitCode.SUCCESS
    assert output["passed"] is True


# ── governance artifacts ────────────────────────────────────────────


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
        "undeclared_dependency_change_downgrade_high",
        "declared_dependency_change_passes",
        "dependency_check_fail_loud",
    } <= ids
    assert "undeclared_dependency_change" in data["severity_policy"]


@pytest.mark.parametrize("name", ["patch_input_v2.example.json", "patch_input_v2.template.json"])
def test_v2_artifacts_validate_against_schema(name):
    import jsonschema

    schema = json.loads(
        (_REPO / "cbsp21" / "patch_input_v2.schema.json").read_text(encoding="utf-8")
    )
    instance = json.loads((_REPO / "cbsp21" / name).read_text(encoding="utf-8"))
    jsonschema.validate(instance, schema)


# ── v2.1.0: sub-file dependency-direction check (born from PR #296) ──────
#
# PR #296 declared a supabase bump and rode an *undeclared* zod
# `^4.4.3 → ^3.25.76` downgrade in the SAME package.json — silently reverting
# PR #293's zod-4 landing. File-level scope saw a declared file and passed. The
# rule below looks INSIDE a declared package.json at per-dependency direction.

_PKG_PATH = "packages/client/package.json"


def _pkgjson(deps: dict) -> str:
    return json.dumps({"name": "client", "dependencies": deps}, indent=2) + "\n"


def _write_dep_manifest(
    root: Path, base: str, declared_files: list[str], *,
    declared_deps: list | None = None, head: str = "HEAD",
) -> Path:
    """Manifest that can additionally declare `scope.dependency_changes` — the
    knob `_write_manifest` does not expose."""
    scope: dict = {"files_expected_to_change": declared_files}
    if declared_deps is not None:
        scope["dependency_changes"] = declared_deps
    manifest = {
        "schema_version": "cbsp21_patch_manifest_v2",
        "scope": scope,
        "diff_range": {"base": base, "head": head, "base_sha": base},
    }
    path = root / "patch.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


@pytest.fixture
def pkg_repo(tmp_path: Path) -> tuple[Path, str]:
    """A repo whose merge-base carries a package.json (supabase + zod), then a
    `feature` branch checked out to receive the change under test."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "scope@example.test")
    _git(tmp_path, "config", "user.name", "Scope Test")
    _commit_file(tmp_path, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.0.0", "zod": "^4.4.3"}))
    base = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    return tmp_path, base


def _dep_findings(findings):
    return [f for f in findings
            if f.metadata["rule_id"] == "pr_scope.undeclared_dependency_change"]


def test_296_undeclared_downgrade_fires_high(pkg_repo):
    """The decisive case: the legit supabase bump is declared, the zod downgrade
    riding alongside it is NOT — it must fire HIGH with direction=downgrade."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.1.0", "zod": "^3.25.76"}))
    manifest = _write_dep_manifest(
        root, base, [_PKG_PATH], declared_deps=["@supabase/supabase-js"])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    dep = _dep_findings(findings)
    assert len(dep) == 1, [f.metadata for f in findings]
    f = dep[0]
    assert f.severity is Severity.HIGH
    assert f.type is AnalyzerType.PR_SCOPE
    assert f.metadata["dependency"] == "zod"
    assert f.metadata["direction"] == "downgrade"
    assert f.metadata["base_version"] == "^4.4.3"
    assert f.metadata["head_version"] == "^3.25.76"


def test_296_legit_supabase_only_stays_silent(pkg_repo):
    """The other half of the decisive assertion: a declared supabase-only bump,
    zod untouched, must produce no dependency-direction finding."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.1.0", "zod": "^4.4.3"}))
    manifest = _write_dep_manifest(
        root, base, [_PKG_PATH], declared_deps=["@supabase/supabase-js"])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    assert "pr_scope.undeclared_dependency_change" not in _rules(findings)


def test_declared_dependency_change_is_silent(pkg_repo):
    """Declaring the zod change in `dependency_changes` legitimizes it."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.1.0", "zod": "^3.25.76"}))
    manifest = _write_dep_manifest(
        root, base, [_PKG_PATH], declared_deps=["@supabase/supabase-js", "zod"])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    assert "pr_scope.undeclared_dependency_change" not in _rules(findings)


def test_undeclared_upgrade_is_medium(pkg_repo):
    """An undeclared *upgrade* is scope drift too, but a milder signal than a
    silent downgrade — MEDIUM, not HIGH."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.0.0", "zod": "^5.0.0"}))
    manifest = _write_dep_manifest(root, base, [_PKG_PATH], declared_deps=[])

    dep = _dep_findings(PrScopeAnalyzer(manifest=manifest, base=base).run(root, []))
    assert len(dep) == 1
    assert dep[0].severity is Severity.MEDIUM
    assert dep[0].metadata["direction"] == "upgrade"


def test_undeclared_package_json_not_double_reported(pkg_repo):
    """The sub-file rule applies only to DECLARED package.json — an undeclared
    one is already covered by pr_scope.undeclared_file, so the dependency rule
    must stay quiet and not double-count."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.0.0", "zod": "^3.25.76"}))
    # package.json is NOT declared; something else is.
    manifest = _write_dep_manifest(root, base, ["docs/notes.md"], declared_deps=[])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    rules = _rules(findings)
    assert "pr_scope.undeclared_dependency_change" not in rules
    assert "pr_scope.undeclared_file" in rules  # the file-level rule still fires


def test_malformed_package_json_is_uncheckable_not_silent(pkg_repo):
    """A package.json that will not parse must fail loud as CRITICAL uncheckable
    — never a silent clean pass."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH, "{ this is not valid json")
    manifest = _write_dep_manifest(root, base, [_PKG_PATH], declared_deps=[])

    findings = PrScopeAnalyzer(manifest=manifest, base=base).run(root, [])
    unc = [f for f in findings
           if f.metadata["rule_id"] == "pr_scope.dependency_check_uncheckable"]
    assert len(unc) == 1
    assert unc[0].severity is Severity.CRITICAL


def test_reverts_base_landing_flag_is_set(tmp_path: Path):
    """When the merge-base commit itself landed the dependency and the branch sets
    it back to the parent value, `reverts_base_landing` is recorded True — the
    exact #293→#296 shape when the landing is the merge-base."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "scope@example.test")
    _git(tmp_path, "config", "user.name", "Scope Test")
    # parent: zod 3
    _commit_file(tmp_path, _PKG_PATH, _pkgjson({"zod": "^3.25.76"}))
    # merge-base: zod 4 lands here
    _commit_file(tmp_path, _PKG_PATH, _pkgjson({"zod": "^4.4.3"}))
    base = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    # branch reverts zod back to the parent value, undeclared
    _commit_file(tmp_path, _PKG_PATH, _pkgjson({"zod": "^3.25.76"}))
    manifest = _write_dep_manifest(tmp_path, base, [_PKG_PATH], declared_deps=[])

    dep = _dep_findings(PrScopeAnalyzer(manifest=manifest, base=base).run(tmp_path, []))
    assert len(dep) == 1
    assert dep[0].severity is Severity.HIGH
    assert dep[0].metadata["reverts_base_landing"] is True


def test_dependency_findings_validate_against_contract(pkg_repo):
    """Every dependency-direction finding is a schema-valid Finding."""
    root, base = pkg_repo
    _commit_file(root, _PKG_PATH,
                 _pkgjson({"@supabase/supabase-js": "^2.1.0", "zod": "^3.25.76"}))
    manifest = _write_dep_manifest(
        root, base, [_PKG_PATH], declared_deps=["@supabase/supabase-js"])

    for f in PrScopeAnalyzer(manifest=manifest, base=base).run(root, []):
        validate_finding(f.to_dict())
