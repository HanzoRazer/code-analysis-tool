"""Contract tests for direct pull-request scan orchestration.

Acquisition and cleanup guarantees are exercised against real Git (a local
bare "origin" exposing ``refs/pull/<n>/head``); only ``gh`` is stubbed.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess

import pytest

from code_audit import pr_scan
from code_audit.pr_scan import (
    PrScanError,
    PrScanOptions,
    PullRequestTarget,
    _parse_pr_number,
    _parse_pr_target,
    _resolve_manifest,
    main,
    resolve_pull_request,
    scan_pull_request,
)

_REAL_RUN = pr_scan._run


# ---------------------------------------------------------------- helpers


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def _commit(repo: Path, name: str, content: str, message: str) -> str:
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def pr_repo(tmp_path: Path):
    """A caller clone whose origin exposes PR #7 under refs/pull/7/head."""
    env_keys = ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")
    old = {k: os.environ.get(k) for k in env_keys}
    os.environ.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@e",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@e",
    )
    try:
        seed = tmp_path / "seed"
        seed.mkdir()
        _git(seed, "init", "-q", "-b", "main")
        base_sha = _commit(seed, "app.py", "x = 1\n", "base")
        _git(seed, "checkout", "-q", "-b", "feature")
        head_sha = _commit(seed, "feature.py", "y = 2\n", "feature")
        _git(seed, "checkout", "-q", "main")

        origin = tmp_path / "origin.git"
        _git(tmp_path, "clone", "-q", "--bare", str(seed), str(origin))
        _git(origin, "update-ref", "refs/pull/7/head", head_sha)
        _git(origin, "branch", "-D", "feature")

        caller = tmp_path / "caller"
        _git(tmp_path, "clone", "-q", str(origin), str(caller))
        (caller / "sentinel.txt").write_text("caller checkout\n", encoding="utf-8")

        # Advance origin/main *after* the PR metadata was captured: the scan
        # must still use the captured base_sha, not the moved branch tip.
        _git(seed, "remote", "add", "origin", str(origin))
        _commit(seed, "later.py", "z = 3\n", "base moved on")
        _git(seed, "push", "-q", "origin", "main")

        target = PullRequestTarget(
            number=7,
            url="https://github.com/o/r/pull/7",
            title="test pr",
            repository="o/r",
            base_ref="main",
            base_sha=base_sha,
            head_ref="feature",
            head_sha=head_sha,
        )
        yield caller.resolve(), target
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _caller_snapshot(caller: Path) -> dict[str, str]:
    return {
        "head": _git(caller, "rev-parse", "HEAD"),
        "branch": _git(caller, "symbolic-ref", "HEAD"),
        "refs": _git(caller, "for-each-ref", "--format=%(refname) %(objectname)"),
        "status": _git(caller, "status", "--porcelain"),
        "worktrees": _git(caller, "worktree", "list", "--porcelain"),
    }


def _stub_resolution(monkeypatch: pytest.MonkeyPatch, target: PullRequestTarget) -> None:
    monkeypatch.setattr(pr_scan, "resolve_pull_request", lambda root, pr, timeout: target)


def _stub_scan(monkeypatch: pytest.MonkeyPatch, seen: dict | None = None) -> None:
    def fake_scan(root, **kwargs):
        if seen is not None:
            seen["root"] = Path(root)
            seen["files"] = sorted(p.name for p in Path(root).iterdir() if p.name != ".git")
            seen["manifest"] = kwargs.get("pr_scope_manifest")
        return object(), {"summary": {"confidence_score": 100, "counts": {"findings_total": 0}}}

    monkeypatch.setattr(pr_scan, "scan_project", fake_scan)


# ---------------------------------------------------------------- parsing


def test_parse_pr_number_accepts_number_and_canonical_url():
    assert _parse_pr_number("296") == 296
    assert _parse_pr_number("https://github.com/HanzoRazer/luthiers-toolbox/pull/296") == 296


def test_parse_pr_target_preserves_url_repository():
    assert _parse_pr_target("296").repository is None
    spec = _parse_pr_target("https://github.com/HanzoRazer/luthiers-toolbox/pull/296/files")
    assert (spec.number, spec.repository) == (296, "HanzoRazer/luthiers-toolbox")


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "abc",
        "٣",  # non-ASCII digit
        "https://example.com/x/pull/1",
        "https://github.com/a/b/issues/1",
        "https://github.com/a/b/c/pull/1",
    ],
)
def test_parse_pr_number_rejects_non_pr_targets(value: str):
    with pytest.raises(PrScanError):
        _parse_pr_number(value)


# ------------------------------------------------- repository attribution


def _fake_gh(
    monkeypatch: pytest.MonkeyPatch,
    *,
    gh_repo: str = "HanzoRazer/luthiers-toolbox",
    origin_url: str = "git@github.com:HanzoRazer/luthiers-toolbox.git",
    pr_meta: dict | None = None,
) -> list[list[str]]:
    calls: list[list[str]] = []
    meta = {
        "number": 296,
        "url": "https://github.com/HanzoRazer/luthiers-toolbox/pull/296",
        "title": "t",
        "baseRefName": "main",
        "baseRefOid": "b" * 40,
        "headRefName": "feature",
        "headRefOid": "a" * 40,
    }
    meta.update(pr_meta or {})

    def fake_run(args, *, cwd, timeout=30.0):
        args = list(args)
        calls.append(args)
        if args[:3] == ["gh", "repo", "view"]:
            out = gh_repo
        elif args[:3] == ["git", "remote", "get-url"]:
            out = origin_url
        elif args[:3] == ["gh", "pr", "view"]:
            out = json.dumps(meta)
        else:
            raise AssertionError(f"unexpected command {args}")
        return subprocess.CompletedProcess(args, 0, out + "\n", "")

    monkeypatch.setattr(pr_scan, "_require_repo_root", lambda root, timeout: Path(root))
    monkeypatch.setattr(pr_scan, "_run", fake_run)
    return calls


def test_url_for_other_repository_is_refused_before_any_pr_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls = _fake_gh(monkeypatch)
    with pytest.raises(PrScanError, match="different repository"):
        resolve_pull_request(tmp_path, "https://github.com/someone-else/other-repo/pull/296")
    assert not any(c[:3] == ["gh", "pr", "view"] for c in calls)


def test_url_for_same_repository_resolves_case_insensitively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _fake_gh(monkeypatch)
    target = resolve_pull_request(tmp_path, "https://github.com/hanzorazer/Luthiers-Toolbox/pull/296")
    assert (target.repository, target.number) == ("HanzoRazer/luthiers-toolbox", 296)


def test_gh_repository_must_match_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _fake_gh(monkeypatch, origin_url="https://github.com/fork-owner/luthiers-toolbox.git")
    with pytest.raises(PrScanError, match="origin is fork-owner/luthiers-toolbox"):
        resolve_pull_request(tmp_path, "296")


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"number": 295}, "PR #295 when PR #296"),
        ({"number": True}, "invalid field: number"),
        ({"url": "https://github.com/other/repo/pull/296"}, "expected canonical"),
        ({"headRefOid": "main"}, "not a full commit SHA"),
        ({"baseRefOid": "B" * 40}, "not a full commit SHA"),
    ],
)
def test_returned_metadata_must_match_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: dict, match: str
):
    _fake_gh(monkeypatch, pr_meta=override)
    with pytest.raises(PrScanError, match=match):
        resolve_pull_request(tmp_path, "296")


# ---------------------------------------------------------------- timeout


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), "abc"])
def test_timeout_must_be_finite_positive(tmp_path: Path, bad):
    with pytest.raises(PrScanError, match="timeout"):
        scan_pull_request(tmp_path, 1, PrScanOptions(timeout=bad))


@pytest.mark.parametrize("bad", ["0", "-5", "nan", "inf"])
def test_cli_rejects_bad_timeout_without_traceback(bad: str, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["1", f"--timeout={bad}"])
    assert excinfo.value.code == 2
    assert "timeout must be a finite positive number" in capsys.readouterr().err


# ------------------------------------------- acquisition (real git) + cleanup


def test_scan_materializes_exact_head_and_base_and_leaves_no_trace(
    pr_repo, monkeypatch: pytest.MonkeyPatch
):
    caller, target = pr_repo
    before = _caller_snapshot(caller)
    _stub_resolution(monkeypatch, target)
    seen: dict = {}

    def fake_scan(root, **kwargs):
        seen["files"] = sorted(p.name for p in Path(root).iterdir() if p.name != ".git")
        seen["head"] = _git(Path(root), "rev-parse", "HEAD")
        # Captured base commit is available locally for base/head comparison,
        # even though origin/main has since moved past it.
        seen["base_present"] = _git(
            caller, "rev-parse", "--verify", f"{target.base_sha}^{{commit}}"
        )
        return object(), {"summary": {}}

    monkeypatch.setattr(pr_scan, "scan_project", fake_scan)

    payload = scan_pull_request(caller, 7)

    assert seen["head"] == target.head_sha
    assert seen["files"] == ["app.py", "feature.py"]
    assert seen["base_present"] == target.base_sha
    execution = payload["execution"]
    assert "read_only" not in execution
    assert execution["source_files_modified"] is False
    assert execution["caller_checkout_mutated"] is False
    assert execution["git_admin_metadata"]["temporarily_modified"] is True
    assert execution["git_admin_metadata"]["fetched_commits"] == {
        "head": target.head_sha,
        "base": target.base_sha,
    }
    assert execution["cleanup"] == {
        "worktree_removed": True,
        "refs_removed": True,
        "verified": True,
    }
    # Branches, remote-tracking refs, status and worktree list are byte-identical.
    assert _caller_snapshot(caller) == before
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""
    assert not (caller / ".git" / "FETCH_HEAD").exists()
    assert (caller / "sentinel.txt").read_text(encoding="utf-8") == "caller checkout\n"


def test_head_sha_mismatch_fails_and_cleans_up(pr_repo, monkeypatch: pytest.MonkeyPatch):
    caller, target = pr_repo
    before = _caller_snapshot(caller)
    moved = replace(target, head_sha=target.base_sha)
    _stub_resolution(monkeypatch, moved)
    _stub_scan(monkeypatch)

    with pytest.raises(PrScanError, match="PR head mismatch"):
        scan_pull_request(caller, 7)
    assert _caller_snapshot(caller) == before


def test_worktree_cleanup_failure_prevents_success(pr_repo, monkeypatch: pytest.MonkeyPatch):
    caller, target = pr_repo
    _stub_resolution(monkeypatch, target)
    _stub_scan(monkeypatch)

    def failing_run(args, *, cwd, timeout=30.0):
        if list(args)[:3] in (["git", "worktree", "remove"], ["git", "worktree", "prune"]):
            raise PrScanError(f"simulated failure: {' '.join(args)}")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_scan, "_run", failing_run)
    with pytest.raises(PrScanError, match="cleanup could not be verified") as excinfo:
        scan_pull_request(caller, 7)
    assert "worktree still registered" in str(excinfo.value)
    # Refs are still released even when the worktree could not be.
    assert _git(caller, "for-each-ref", "refs/code-audit") == ""
    _git(caller, "worktree", "prune")


def test_ref_cleanup_failure_prevents_success(pr_repo, monkeypatch: pytest.MonkeyPatch):
    caller, target = pr_repo
    _stub_resolution(monkeypatch, target)
    _stub_scan(monkeypatch)

    def failing_run(args, *, cwd, timeout=30.0):
        if list(args)[:2] == ["git", "update-ref"]:
            raise PrScanError("simulated update-ref failure")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_scan, "_run", failing_run)
    with pytest.raises(PrScanError, match="private refs still present"):
        scan_pull_request(caller, 7)


def test_cleanup_failure_is_attached_to_primary_error_not_hidden(
    pr_repo, monkeypatch: pytest.MonkeyPatch
):
    caller, target = pr_repo
    _stub_resolution(monkeypatch, target)

    def boom(root, **kwargs):
        raise PrScanError("primary scan failure")

    monkeypatch.setattr(pr_scan, "scan_project", boom)

    def failing_run(args, *, cwd, timeout=30.0):
        if list(args)[:3] in (["git", "worktree", "remove"], ["git", "worktree", "prune"]):
            raise PrScanError("simulated failure")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_scan, "_run", failing_run)
    with pytest.raises(PrScanError, match="primary scan failure") as excinfo:
        scan_pull_request(caller, 7)
    assert any("cleanup also failed" in n for n in excinfo.value.__notes__)
    _git(caller, "worktree", "prune")


def test_cli_reports_cleanup_failure_as_exit_2(pr_repo, monkeypatch: pytest.MonkeyPatch, capsys):
    caller, target = pr_repo
    _stub_resolution(monkeypatch, target)
    _stub_scan(monkeypatch)

    def failing_run(args, *, cwd, timeout=30.0):
        if list(args)[:3] in (["git", "worktree", "remove"], ["git", "worktree", "prune"]):
            raise PrScanError("simulated failure")
        return _REAL_RUN(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(pr_scan, "_run", failing_run)
    assert main(["7", "--repo-root", str(caller)]) == 2
    assert "cleanup could not be verified" in capsys.readouterr().err
    _git(caller, "worktree", "prune")


# ---------------------------------------------------------------- manifest


def test_pr_scope_manifest_rejects_lexical_escape(pr_repo, monkeypatch: pytest.MonkeyPatch):
    caller, target = pr_repo
    before = _caller_snapshot(caller)
    _stub_resolution(monkeypatch, target)
    _stub_scan(monkeypatch)

    with pytest.raises(PrScanError, match="safe path"):
        scan_pull_request(caller, 7, PrScanOptions(pr_scope_manifest=Path("../manifest.json")))
    assert _caller_snapshot(caller) == before


def test_pr_scope_manifest_resolved_inside_worktree(pr_repo, monkeypatch: pytest.MonkeyPatch):
    caller, target = pr_repo
    _stub_resolution(monkeypatch, target)
    seen: dict = {}
    _stub_scan(monkeypatch, seen)

    payload = scan_pull_request(caller, 7, PrScanOptions(pr_scope_manifest="app.py"))
    assert seen["manifest"].name == "app.py"
    assert payload["execution"]["pr_scope_manifest"] == "app.py"


def test_pr_scope_manifest_symlink_escape_is_refused(tmp_path: Path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = worktree / "cbsp21.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    with pytest.raises(PrScanError, match="resolves outside the PR worktree"):
        _resolve_manifest(worktree, Path("cbsp21.json"))


def test_pr_scope_manifest_missing_is_refused(tmp_path: Path):
    with pytest.raises(PrScanError, match="does not exist"):
        _resolve_manifest(tmp_path, Path("nope.json"))

