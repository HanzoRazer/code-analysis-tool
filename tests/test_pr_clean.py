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


def _finding(rule: str, path: str, fp: str, line: int = 1, end: int | None = None) -> dict:
    return {
        "fingerprint": fp,
        "metadata": {"rule_id": rule},
        "location": {"path": path, "line_start": line, "line_end": end},
    }


_COMPLETE = {
    "assessable": True,
    "files_scanned": 1,
    "analyzers_total": 1,
    "analyzers_ok": 1,
    "degraded": [],
    "reasons": [],
}


def _result(*findings: dict, integrity: dict | None = _COMPLETE) -> dict:
    result = {"schema_version": "run_result_v2", "findings_raw": list(findings)}
    if integrity is not None:
        result["scan_integrity"] = integrity
    return result


def _degraded(analyzer_id: str, status: str, *, assessable: bool = True) -> dict:
    return {
        **_COMPLETE,
        "assessable": assessable,
        "degraded": [
            {"analyzer_id": analyzer_id, "status": status, "is_critical": False,
             "duration_s": None}
        ],
        "reasons": [] if assessable else [f"missing_capability:{analyzer_id}"],
    }


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
        return object(), _result(*findings)

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
    # Here the captured base IS the branch point, so the merge-base equals it.
    assert report["pull_request"]["comparison_base_sha"] == target.base_sha
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
    # Same scan configuration on base: the identical manifest is applied there too.
    assert seen["pr-base"]["manifest"] == seen["pr-head"]["manifest"]
    assert report["comparability"]["pr_scope_manifest_applied_to"] == ["head", "base"]
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
        ({"rule_id": "R1"}, [_finding("R1", "a.py", "x")], [_finding("R1", "a.py", "y")],
         "needs_human_decision"),
        ({"rule_id": "R1"}, [], [_finding("R1", "a.py", "x")], "unsupported_by_tool"),
        ({"rule_id": "R1", "path": "b.py"}, [_finding("R1", "a.py", "x")], [],
         "unsupported_by_tool"),
        ({"rule_id": "R1", "path": "sub\\a.py"}, [_finding("R1", "sub/a.py", "x")], [],
         "pr_introduced"),
        ({}, [_finding("R1", "a.py", "x")], [], "needs_human_decision"),
        # Base has A; head has A plus a new B. An unlocated claim is ambiguous,
        # never silently pre_existing.
        ({"rule_id": "R1", "path": "a.py"},
         [_finding("R1", "a.py", "A", 3), _finding("R1", "a.py", "B", 9)],
         [_finding("R1", "a.py", "A", 3)], "needs_human_decision"),
        # ...the claim's line pins B, which is new while A persists.
        ({"rule_id": "R1", "path": "a.py", "line": 9},
         [_finding("R1", "a.py", "A", 3), _finding("R1", "a.py", "B", 9)],
         [_finding("R1", "a.py", "A", 3)], "pr_introduced"),
        # ...the claim's line pins A, which exists on base.
        ({"rule_id": "R1", "path": "a.py", "line": 3},
         [_finding("R1", "a.py", "A", 3), _finding("R1", "a.py", "B", 9)],
         [_finding("R1", "a.py", "A", 3)], "pre_existing"),
        # Line inside a multi-line finding span.
        ({"rule_id": "R1", "path": "a.py", "line": 5},
         [_finding("R1", "a.py", "B", 4, 6)], [], "pr_introduced"),
        # Rule/path reproduced, but nothing at the claimed line.
        ({"rule_id": "R1", "path": "a.py", "line": 50},
         [_finding("R1", "a.py", "B", 9)], [], "needs_human_decision"),
        # A line without a path cannot be located.
        ({"rule_id": "R1", "line": 9}, [_finding("R1", "a.py", "B", 9)], [],
         "needs_human_decision"),
        # Base finding gone while a new one appeared: identity may have changed.
        ({"rule_id": "R1", "path": "a.py", "line": 9}, [_finding("R1", "a.py", "B", 9)],
         [_finding("R1", "a.py", "A", 3)], "needs_human_decision"),
    ],
)
def test_classification(claim, head, base, status):
    claim = {"claim_id": "C1", "summary": "s", **claim}
    out = verify_assessment(
        _assessment(claim),
        base_run_result=_result(*base),
        head_run_result=_result(*head),
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


# ------------------------------------------------ scan-result integrity


@pytest.mark.parametrize(
    ("result", "match"),
    [
        ({"findings": []}, "findings_raw"),
        ({"findings_raw": {}}, "findings_raw"),
        ({"findings_raw": ["x"]}, "must be an object"),
        ({"findings_raw": [{"location": {"path": "a.py"}}]}, "fingerprint"),
        ({"findings_raw": [{"fingerprint": "f"}]}, "location"),
        ({"findings_raw": [{"fingerprint": "f", "location": {"path": ""}}]}, "path"),
        ({"findings_raw": [{"fingerprint": "f", "location": {"path": "a", "line_start": True}}]},
         "line_start"),
    ],
)
def test_malformed_scan_result_is_rejected_not_read_as_empty(result, match):
    good = _result()
    with pytest.raises(PrCleanError, match=match):
        verify_assessment(_assessment(), base_run_result=good, head_run_result=result)
    with pytest.raises(PrCleanError, match=match):
        verify_assessment(_assessment(), base_run_result=result, head_run_result=good)


def test_verifies_against_real_scanner_output(tmp_path):
    """Real scan_project output (run_result_v1 findings_raw) is what gets compared."""
    from code_audit.api import scan_project

    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (head / "a.py").write_text(
        "def f():\n    try:\n        pass\n    except:\n        pass\n", encoding="utf-8"
    )
    _rr, base_result = scan_project(base, ci_mode=True)
    _rr, head_result = scan_project(head, ci_mode=True)
    out = verify_assessment(
        _assessment({"claim_id": "C1", "summary": "bare except", "rule_id": "EXC-BARE-001",
                     "path": "a.py", "line": 4}),
        base_run_result=base_result,
        head_run_result=head_result,
    )
    assert out["claims"][0]["status"] == "pr_introduced"


@pytest.mark.parametrize(
    ("integrity", "match"),
    [
        # Noncritical crash: the scan stays assessable (YELLOW) but is degraded.
        (_degraded("exceptions", "failed"), "exceptions=failed"),
        # Missing parser: the runner logs only at INFO ("skipping"), so a
        # warning-log probe never saw it. Structured evidence must.
        (_degraded("js_ts_security", "missing_capability", assessable=False),
         "js_ts_security=missing_capability"),
        ({**_COMPLETE, "assessable": False, "reasons": ["no_source_files"]},
         "no_source_files"),
        (None, "no scan_integrity evidence"),
        ({**_COMPLETE, "degraded": None}, "degraded must be an array"),
    ],
    ids=["degraded", "missing_capability", "not_assessable", "absent", "malformed"],
)
def test_incomplete_scan_fails_closed_and_cleans_up(wired, monkeypatch, integrity, match):
    """A base scan that is not complete per scan_integrity is not comparable."""
    caller, _target, _seen = wired
    before = _caller_snapshot(caller)

    def partial_scan(root, **kwargs):
        if kwargs["project_id"].startswith("pr-base:"):
            return object(), _result(integrity=integrity)
        return object(), _result()

    monkeypatch.setattr(pr_clean, "scan_project", partial_scan)
    with pytest.raises(PrCleanError, match="pr-base:.*" + match):
        build_plan(caller, 7, assessment=_assessment())
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""


def test_report_states_comparability(wired):
    caller, _target, _seen = wired
    report = build_plan(caller, 7, assessment=_assessment())
    assert report["comparability"] == {
        "scans_completed": True,
        "analyzers_skipped": 0,
        "identical_scan_configuration": True,
        "pr_scope_manifest_applied_to": [],
    }


def test_cli_incomplete_scan_exits_2(wired, monkeypatch, tmp_path, capsys):
    caller, _target, _seen = wired

    def partial_scan(root, **kwargs):
        return object(), _result(integrity=_degraded("x", "failed"))

    monkeypatch.setattr(pr_clean, "scan_project", partial_scan)
    assessment = tmp_path / "a.json"
    assessment.write_text(json.dumps(_assessment()), encoding="utf-8")
    assert main(["7", "--repo-root", str(caller), "--assessment", str(assessment)]) == 2
    assert "scan incomplete" in capsys.readouterr().err
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""


# ------------------------------------------------ merge-base comparison


def _commit_files(repo: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", *files)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def diverged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """main fixed a defect AFTER the PR branched; the PR adds a new one.

        branch point M: old.py=BUG:old  same.py=BUG:same
        main tip     T: old.py=fixed    (captured target base)
        PR head      H: M + new.py=BUG:new

    Findings are derived from file content (one R1 finding per BUG marker), so
    classification exercises the real commits git checked out.
    """
    for key in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.setenv(key, "t")
    for key in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(key, "t@e")
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-q", "-b", "main")
    branch_point = _commit_files(
        seed, {"old.py": "BUG:old\n", "same.py": "BUG:same\n"}, "branch point"
    )
    _git(seed, "checkout", "-q", "-b", "feature")
    head = _commit_files(seed, {"new.py": "BUG:new\n"}, "pr adds defect")
    _git(seed, "checkout", "-q", "main")
    tip = _commit_files(seed, {"old.py": "fixed\n"}, "main fixes old defect")
    _git(seed, "checkout", "-q", "--orphan", "unrelated")
    unrelated = _commit_files(seed, {"other.py": "z\n"}, "unrelated history")
    _git(seed, "checkout", "-q", "main")

    origin = tmp_path / "origin.git"
    _git(tmp_path, "clone", "-q", "--bare", str(seed), str(origin))
    _git(origin, "update-ref", "refs/pull/7/head", head)
    _git(origin, "branch", "-D", "feature")
    caller = tmp_path / "caller"
    _git(tmp_path, "clone", "-q", str(origin), str(caller))

    target = pr_scan.PullRequestTarget(
        number=7,
        url="https://github.com/o/r/pull/7",
        title="diverged",
        repository="o/r",
        base_ref="main",
        base_sha=tip,
        head_ref="feature",
        head_sha=head,
    )
    seen: dict = {}
    monkeypatch.setattr(pr_clean, "resolve_pull_request", lambda root, pr, timeout: target)
    monkeypatch.setattr(pr_clean, "scan_project", _content_scan(seen))
    return caller.resolve(), target, seen, branch_point, unrelated


def _content_scan(seen: dict):
    """Fake scanner: one R1 finding per ``BUG:`` file, keyed by its content."""

    def scan(root, **kwargs):
        kind = kwargs["project_id"].split(":", 1)[0]
        seen[kind] = _git(Path(root), "rev-parse", "HEAD")
        findings = [
            _finding("R1", p.name, f"fp-{p.name}-{p.read_text(encoding='utf-8').strip()}")
            for p in sorted(Path(root).glob("*.py"))
            if p.read_text(encoding="utf-8").startswith("BUG:")
        ]
        return object(), _result(*findings)

    return scan


def _claim(cid: str, path: str) -> dict:
    return {"claim_id": cid, "summary": cid, "rule_id": "R1", "path": path}


def test_merge_base_is_the_classification_baseline(diverged):
    caller, target, seen, branch_point, _unrelated = diverged
    before = _caller_snapshot(caller)

    report = build_plan(
        caller,
        7,
        assessment=_assessment(
            _claim("fixed_on_main_later", "old.py"),
            _claim("introduced_by_pr", "new.py"),
            _claim("identical_both_sides", "same.py"),
        ),
    )

    status = {c["claim_id"]: c["status"] for c in report["assessment_verification"]["claims"]}
    # old.py still has the defect on the PR head, but it predates the branch
    # point; main's later fix must not make it look PR-introduced.
    assert status == {
        "fixed_on_main_later": "pre_existing",
        "introduced_by_pr": "pr_introduced",
        "identical_both_sides": "pre_existing",
    }
    assert seen == {"pr-head": target.head_sha, "pr-base": branch_point}
    pr = report["pull_request"]
    assert pr["head_sha"] == target.head_sha
    assert pr["target_base_sha"] == target.base_sha
    assert pr["comparison_base_sha"] == branch_point != target.base_sha
    assert pr["comparison_strategy"] == "merge_base"
    assert "base_sha" not in pr
    # Main-side changes (old.py) are not attributed to the PR.
    assert report["scope"]["changed_files"] == ["new.py"]
    assert report["execution"]["cleanup"]["verified"] is True
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""


def test_no_merge_base_fails_closed(diverged, monkeypatch, tmp_path, capsys):
    caller, target, seen, _bp, unrelated = diverged
    before = _caller_snapshot(caller)
    orphan_target = replace(target, base_sha=unrelated)
    monkeypatch.setattr(pr_clean, "resolve_pull_request", lambda r, p, timeout: orphan_target)

    with pytest.raises(PrCleanError, match="cannot establish merge-base"):
        build_plan(caller, 7, assessment=_assessment())
    assert "pr-base" not in seen and "pr-head" not in seen
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""

    assessment = tmp_path / "a.json"
    assessment.write_text(json.dumps(_assessment()), encoding="utf-8")
    assert main(["7", "--repo-root", str(caller), "--assessment", str(assessment)]) == 2
    assert "cannot establish merge-base" in capsys.readouterr().err


@pytest.mark.parametrize(
    "stdout", ["", "not-a-sha\n", "a" * 40 + "\n" + "b" * 40 + "\n"], ids=["empty", "junk", "two"]
)
def test_ambiguous_or_malformed_merge_base_fails_closed(diverged, monkeypatch, stdout):
    """Criss-cross histories (several merge-bases) are not silently resolved."""
    import subprocess

    caller, _target, seen, _bp, _unrelated = diverged

    def run(args, *, cwd, timeout=30.0):
        if list(args)[:2] == ["git", "merge-base"]:
            return subprocess.CompletedProcess(list(args), 0, stdout, "")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_clean, "_run", run)
    with pytest.raises(PrCleanError, match="expected exactly one commit"):
        build_plan(caller, 7, assessment=_assessment())
    assert not seen
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""
    assert _git(caller, "worktree", "list", "--porcelain").count("worktree ") == 1
