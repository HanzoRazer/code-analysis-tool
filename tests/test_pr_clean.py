"""Contract tests for PR-CLEAN-001 verify-and-report planning.

Acquisition/cleanup run against real git via the PR-SCAN fixture (local bare
origin exposing refs/pull/7/head, with origin/main advanced after capture);
only ``gh`` resolution and ``scan_project`` are stubbed.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from code_audit import pr_clean, pr_scan
from code_audit.pr_clean import PrCleanError, build_plan, main, verify_assessment
from code_audit.pr_scan import PrScanError
from tests.test_pr_scan import _caller_snapshot, _git, pr_repo  # noqa: F401  (fixture)

_REAL_RUN = pr_scan._run


def _assessment(*claims: dict) -> dict:
    return {"schema_version": "pr_clean_assessment_v1", "source": "test", "claims": list(claims)}


def _finding(rule: str, path: str, fp: str | None = None) -> dict:
    f = {"metadata": {"rule_id": rule}, "location": {"path": path}}
    if fp:
        f["fingerprint"] = fp
    return f


@pytest.fixture
def wired(pr_repo, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    """pr_repo with gh resolution stubbed and scan_project recording each tree."""
    caller, target = pr_repo
    monkeypatch.setattr(pr_clean, "resolve_pull_request", lambda root, pr, timeout: target)
    seen: dict = {}

    def fake_scan(root, **kwargs):
        kind = kwargs["project_id"].split(":", 1)[0]
        seen[kind] = {
            "head": _git(Path(root), "rev-parse", "HEAD"),
            "files": sorted(p.name for p in Path(root).iterdir() if p.name != ".git"),
            "manifest": kwargs.get("pr_scope_manifest"),
        }
        findings = [_finding("R1", "feature.py", "fp-new")] if kind == "pr-head" else []
        return object(), {"findings": findings}

    monkeypatch.setattr(pr_clean, "scan_project", fake_scan)
    return caller, target, seen


def _fail_worktree_removal(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_run(args, *, cwd, timeout=30.0):
        if list(args)[:3] in (["git", "worktree", "remove"], ["git", "worktree", "prune"]):
            raise PrScanError("simulated failure")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_scan, "_run", failing_run)
    monkeypatch.setattr(pr_clean, "_run", failing_run)


# ------------------------------------------------ acquisition + cleanup


def test_plan_scans_exact_head_and_captured_base_and_leaves_no_trace(wired):
    caller, target, seen = wired
    before = _caller_snapshot(caller)

    report = build_plan(
        caller, 7, assessment=_assessment({"claim_id": "C1", "summary": "s", "rule_id": "R1"})
    )

    assert seen["pr-head"]["head"] == target.head_sha
    # Captured base commit, even though origin/main has moved past it.
    assert seen["pr-base"]["head"] == target.base_sha
    assert seen["pr-base"]["files"] == ["app.py"]
    assert report["scope"]["changed_files"] == ["feature.py"]
    assert report["assessment_verification"]["counts"]["pr_introduced"] == 1
    execution = report["execution"]
    assert execution["source_files_modified"] is False
    assert execution["caller_checkout_mutated"] is False
    assert execution["git_admin_metadata"]["temporarily_modified"] is True
    assert execution["cleanup"] == {
        "worktrees_removed": True,
        "refs_removed": True,
        "verified": True,
    }
    assert "mutations_performed" not in report
    # Branches, remote-tracking refs (origin/main NOT advanced), status and
    # worktree list are identical; no private refs, no FETCH_HEAD.
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""
    assert not (caller / ".git" / "FETCH_HEAD").exists()


def test_invalid_assessment_fails_before_any_git_activity(wired, monkeypatch):
    caller, _target, _seen = wired
    before = _caller_snapshot(caller)
    monkeypatch.setattr(
        pr_clean,
        "_materialize_pr_head",
        lambda *a, **k: pytest.fail("must not materialize with an invalid assessment"),
    )
    with pytest.raises(PrCleanError, match="schema_version"):
        build_plan(caller, 7, assessment={"schema_version": "nope"})
    assert _caller_snapshot(caller) == before


def test_head_mismatch_fails_and_leaves_no_trace(pr_repo, monkeypatch):  # noqa: F811
    caller, target = pr_repo
    before = _caller_snapshot(caller)
    moved = replace(target, head_sha=target.base_sha)
    monkeypatch.setattr(pr_clean, "resolve_pull_request", lambda root, pr, timeout: moved)
    with pytest.raises(PrScanError, match="PR head mismatch"):
        build_plan(caller, 7, assessment=_assessment())
    assert _caller_snapshot(caller) == before


def test_scan_failure_cleans_both_worktrees_and_refs(wired, monkeypatch):
    caller, _target, _seen = wired
    before = _caller_snapshot(caller)

    def boom(root, **kwargs):
        raise RuntimeError("scanner crashed")

    monkeypatch.setattr(pr_clean, "scan_project", boom)
    with pytest.raises(RuntimeError, match="scanner crashed"):
        build_plan(caller, 7, assessment=_assessment())
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""


def test_unverified_cleanup_prevents_report(wired, monkeypatch):
    caller, _target, _seen = wired
    _fail_worktree_removal(monkeypatch)
    with pytest.raises(PrCleanError, match="cleanup could not be verified") as excinfo:
        build_plan(caller, 7, assessment=_assessment())
    assert "worktree still registered" in str(excinfo.value)
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""
    _git(caller, "worktree", "prune")


def test_cleanup_failure_attached_to_primary_error(wired, monkeypatch):
    caller, _target, _seen = wired
    _fail_worktree_removal(monkeypatch)

    def boom(root, **kwargs):
        raise PrCleanError("primary failure")

    monkeypatch.setattr(pr_clean, "scan_project", boom)
    with pytest.raises(PrCleanError, match="primary failure") as excinfo:
        build_plan(caller, 7, assessment=_assessment())
    assert any("cleanup also failed" in n for n in excinfo.value.__notes__)
    _git(caller, "worktree", "prune")


def test_cli_cleanup_failure_exits_2(wired, monkeypatch, tmp_path, capsys):
    caller, _target, _seen = wired
    _fail_worktree_removal(monkeypatch)
    assessment = tmp_path / "a.json"
    assessment.write_text(json.dumps(_assessment()), encoding="utf-8")
    assert main(["7", "--repo-root", str(caller), "--assessment", str(assessment)]) == 2
    assert "cleanup could not be verified" in capsys.readouterr().err
    _git(caller, "worktree", "prune")


# ------------------------------------------------ manifest + timeout


def test_manifest_lexical_escape_refused(wired):
    caller, _target, _seen = wired
    before = _caller_snapshot(caller)
    with pytest.raises(PrScanError, match="safe path"):
        build_plan(caller, 7, assessment=_assessment(), pr_scope_manifest="../m.json")
    assert _caller_snapshot(caller) == before


def test_manifest_resolved_inside_head_worktree(wired):
    caller, _target, seen = wired
    report = build_plan(caller, 7, assessment=_assessment(), pr_scope_manifest="feature.py")
    assert seen["pr-head"]["manifest"].name == "feature.py"
    assert report["scope"]["pr_scope_manifest"] == "feature.py"


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
def test_timeout_must_be_finite_positive(tmp_path, bad):
    with pytest.raises(PrScanError, match="timeout"):
        build_plan(tmp_path, 1, assessment=_assessment(), timeout=bad)


def test_cli_rejects_bad_timeout(tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["1", "--assessment", str(tmp_path / "a.json"), "--timeout=0"])
    assert excinfo.value.code == 2
    assert "finite positive" in capsys.readouterr().err


# ------------------------------------------------ claim classification


@pytest.mark.parametrize(
    ("claim", "head", "base", "status"),
    [
        ({"rule_id": "R1"}, [_finding("R1", "a.py", "x")], [], "pr_introduced"),
        ({"rule_id": "R1"}, [_finding("R1", "a.py", "x")], [_finding("R1", "a.py", "x")],
         "pre_existing"),
        ({"rule_id": "R1"}, [_finding("R1", "a.py")], [_finding("R1", "a.py")], "pre_existing"),
        ({"rule_id": "R1"}, [_finding("R1", "a.py", "x")], [_finding("R1", "a.py", "y")],
         "needs_human_decision"),
        ({"rule_id": "R1"}, [], [_finding("R1", "a.py", "x")], "unsupported_by_tool"),
        ({"rule_id": "R1", "path": "b.py"}, [_finding("R1", "a.py", "x")], [],
         "unsupported_by_tool"),
        ({"rule_id": "R1", "path": "sub\\a.py"}, [_finding("R1", "sub/a.py", "x")], [],
         "pr_introduced"),
        ({}, [_finding("R1", "a.py", "x")], [], "needs_human_decision"),
    ],
)
def test_classification(claim, head, base, status):
    claim = {"claim_id": "C1", "summary": "s", **claim}
    out = verify_assessment(
        _assessment(claim),
        base_run_result={"findings": base},
        head_run_result={"findings": head},
    )
    assert out["claims"][0]["status"] == status
    assert out["counts"][status] == 1
    expected = "human_repair_candidate" if status == "pr_introduced" else "no_automatic_repair"
    assert out["claims"][0]["repair_disposition"] == expected


@pytest.mark.parametrize(
    ("assessment", "match"),
    [
        ([], "JSON object"),
        ({"schema_version": "pr_clean_assessment_v1", "source": "", "claims": []}, "source"),
        ({"schema_version": "pr_clean_assessment_v1", "source": "s", "claims": {}}, "array"),
        (_assessment({"claim_id": "C1", "summary": "s"}, {"claim_id": "C1", "summary": "t"}),
         "duplicate"),
        (_assessment({"claim_id": "C1", "summary": "s", "line": True}), "positive integer"),
        (_assessment({"claim_id": "C1", "summary": "s", "rule_id": " "}), "rule_id"),
    ],
)
def test_assessment_validation(assessment, match, tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps(assessment), encoding="utf-8")
    with pytest.raises(PrCleanError, match=match):
        pr_clean._load_assessment(path)
