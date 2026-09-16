"""Contract tests for direct pull-request scan orchestration."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from code_audit.pr_scan import (
    PrScanError,
    PullRequestTarget,
    _parse_pr_number,
    scan_pull_request,
)


def test_parse_pr_number_accepts_number_and_canonical_url():
    assert _parse_pr_number("296") == 296
    assert _parse_pr_number("https://github.com/HanzoRazer/luthiers-toolbox/pull/296") == 296


@pytest.mark.parametrize(
    "value",
    ["0", "-1", "abc", "https://example.com/x/pull/1", "https://github.com/a/b/issues/1"],
)
def test_parse_pr_number_rejects_non_pr_targets(value: str):
    with pytest.raises(PrScanError):
        _parse_pr_number(value)


def test_scan_pull_request_uses_temp_worktree_and_preserves_caller_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = PullRequestTarget(
        number=12,
        url="https://github.com/o/r/pull/12",
        title="test pr",
        repository="o/r",
        base_ref="main",
        base_sha="b" * 40,
        head_ref="feature/x",
        head_sha="a" * 40,
    )
    before = repo / "sentinel.txt"
    before.write_text("caller checkout\n", encoding="utf-8")

    monkeypatch.setattr("code_audit.pr_scan._require_repo_root", lambda root, timeout: repo)
    monkeypatch.setattr("code_audit.pr_scan.resolve_pull_request", lambda root, pr, timeout: target)

    def fake_materialize(root, resolved, worktree, timeout):
        worktree.mkdir(parents=True)
        (worktree / "app.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr("code_audit.pr_scan._materialize_pr_head", fake_materialize)
    monkeypatch.setattr(
        "code_audit.pr_scan.scan_project",
        lambda root, **kwargs: (
            object(),
            {"summary": {"confidence_score": 100, "counts": {"findings_total": 0}}},
        ),
    )

    calls: list[list[str]] = []

    def fake_subprocess_run(args, **kwargs):
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("code_audit.pr_scan.subprocess.run", fake_subprocess_run)

    payload = scan_pull_request(repo, 12)

    assert payload["schema_version"] == "pr_scan_v1"
    assert payload["pull_request"]["head_sha"] == "a" * 40
    assert payload["execution"]["read_only"] is True
    assert payload["execution"]["caller_checkout_mutated"] is False
    assert before.read_text(encoding="utf-8") == "caller checkout\n"
    assert any(call[:3] == ["git", "worktree", "remove"] for call in calls)


def test_pr_scope_manifest_must_be_relative_and_inside_pr_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = PullRequestTarget(
        number=12,
        url="https://github.com/o/r/pull/12",
        title="test pr",
        repository="o/r",
        base_ref="main",
        base_sha="b" * 40,
        head_ref="feature/x",
        head_sha="a" * 40,
    )
    monkeypatch.setattr("code_audit.pr_scan._require_repo_root", lambda root, timeout: repo)
    monkeypatch.setattr("code_audit.pr_scan.resolve_pull_request", lambda root, pr, timeout: target)

    def fake_materialize(root, resolved, worktree, timeout):
        worktree.mkdir(parents=True)

    monkeypatch.setattr("code_audit.pr_scan._materialize_pr_head", fake_materialize)
    monkeypatch.setattr(
        "code_audit.pr_scan.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
    )

    with pytest.raises(PrScanError, match="safe path"):
        scan_pull_request(repo, 12, pr_scope_manifest=Path("../manifest.json"))
