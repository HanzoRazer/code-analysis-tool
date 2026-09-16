"""Read-only pull-request scan orchestration.

This module makes a GitHub pull request a first-class scan target without
mutating the caller's checkout.  It resolves PR metadata with ``gh``, fetches
the exact PR head into the local repository, materializes that commit in a
temporary detached worktree, and runs the existing ``scan_project`` pipeline
against the resulting tree.

V1 is deliberately observation-only:

* no PR comments or reviews
* no merge/update actions
* no new blocking policy
* no checkout/branch switch in the caller's working tree

Usage::

    python -m code_audit.pr_scan 296 --repo-root . --json
    python -m code_audit.pr_scan https://github.com/OWNER/REPO/pull/296 --repo-root .

An optional ``--pr-scope-manifest`` path is interpreted relative to the PR
worktree and activates the existing ``pr_scope`` analyzer during the scan.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from code_audit.api import scan_project
from code_audit.utils.json_norm import stable_json_dump

_DEFAULT_TIMEOUT_SECONDS = 30.0
_PR_URL_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/pull/(?P<number>[1-9][0-9]*)(?:/.*)?$")


class PrScanError(RuntimeError):
    """Raised when PR resolution/materialization cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class PullRequestTarget:
    number: int
    url: str
    title: str
    repository: str
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str


def _run(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(args),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise PrScanError(f"command failed to execute: {' '.join(args)}: {exc}") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise PrScanError(
            f"command failed ({completed.returncode}): {' '.join(args)}"
            + (f": {stderr}" if stderr else "")
        )
    return completed


def _parse_pr_number(value: str) -> int:
    raw = value.strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    match = _PR_URL_RE.fullmatch(raw)
    if match:
        return int(match.group("number"))
    raise PrScanError(
        "PR target must be a positive pull-request number or a canonical "
        "https://github.com/OWNER/REPO/pull/NUMBER URL"
    )


def _require_repo_root(repo_root: Path, *, timeout: float) -> Path:
    root = repo_root.resolve()
    if not root.is_dir():
        raise PrScanError(f"repo root is not a directory: {root}")
    probe = _run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        timeout=timeout,
    ).stdout.strip()
    actual = Path(probe).resolve()
    if actual != root:
        raise PrScanError(
            f"--repo-root must name the Git repository root: expected {actual}, got {root}"
        )
    return root


def _repo_name(root: Path, *, timeout: float) -> str:
    result = _run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        cwd=root,
        timeout=timeout,
    ).stdout.strip()
    if not result or "/" not in result:
        raise PrScanError("unable to resolve GitHub repository name with gh")
    return result


def resolve_pull_request(
    repo_root: Path,
    pr: str | int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> PullRequestTarget:
    """Resolve immutable PR refs from GitHub using the authenticated ``gh`` CLI."""
    root = _require_repo_root(repo_root, timeout=timeout)
    number = _parse_pr_number(str(pr))
    repository = _repo_name(root, timeout=timeout)

    fields = "number,url,title,baseRefName,baseRefOid,headRefName,headRefOid"
    raw = _run(
        [
            "gh",
            "pr",
            "view",
            str(number),
            "--repo",
            repository,
            "--json",
            fields,
        ],
        cwd=root,
        timeout=timeout,
    ).stdout
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PrScanError(f"gh returned invalid PR metadata JSON: {exc}") from exc

    required = {
        "number": int,
        "url": str,
        "title": str,
        "baseRefName": str,
        "baseRefOid": str,
        "headRefName": str,
        "headRefOid": str,
    }
    for key, expected_type in required.items():
        value = data.get(key)
        if not isinstance(value, expected_type) or (isinstance(value, str) and not value):
            raise PrScanError(f"gh PR metadata missing/invalid field: {key}")

    return PullRequestTarget(
        number=int(data["number"]),
        url=data["url"],
        title=data["title"],
        repository=repository,
        base_ref=data["baseRefName"],
        base_sha=data["baseRefOid"],
        head_ref=data["headRefName"],
        head_sha=data["headRefOid"],
    )


def _materialize_pr_head(
    root: Path,
    target: PullRequestTarget,
    worktree: Path,
    *,
    timeout: float,
) -> None:
    # GitHub exposes PR heads under refs/pull/<n>/head even for fork PRs. Fetch
    # into a private code-audit namespace so the caller's branches are untouched.
    local_ref = f"refs/code-audit/pr/{target.number}/head"
    _run(
        [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            f"refs/pull/{target.number}/head:{local_ref}",
        ],
        cwd=root,
        timeout=timeout,
    )

    resolved = _run(
        ["git", "rev-parse", local_ref],
        cwd=root,
        timeout=timeout,
    ).stdout.strip()
    if resolved != target.head_sha:
        raise PrScanError(
            "PR head moved while materializing: "
            f"GitHub reported {target.head_sha}, fetched {resolved}"
        )

    # Fetch the base branch as remote-tracking context for diff-aware analyzers.
    _run(
        ["git", "fetch", "--no-tags", "origin", target.base_ref],
        cwd=root,
        timeout=timeout,
    )
    _run(
        ["git", "worktree", "add", "--detach", str(worktree), target.head_sha],
        cwd=root,
        timeout=timeout,
    )


def scan_pull_request(
    repo_root: str | Path,
    pr: str | int,
    *,
    ci_mode: bool = True,
    enable_js_ts: bool = True,
    pr_scope_manifest: str | Path | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Scan the exact head tree of a GitHub pull request.

    The caller's working tree is never checked out or reset.  A temporary
    detached worktree is always removed before return/raise.
    """
    root = _require_repo_root(Path(repo_root), timeout=timeout)
    target = resolve_pull_request(root, pr, timeout=timeout)

    with tempfile.TemporaryDirectory(prefix="code-audit-pr-scan-") as temp_dir:
        worktree = Path(temp_dir) / "worktree"
        materialized = False
        try:
            _materialize_pr_head(root, target, worktree, timeout=timeout)
            materialized = True

            manifest: Path | None = None
            if pr_scope_manifest is not None:
                requested = Path(pr_scope_manifest)
                if requested.is_absolute() or ".." in requested.parts:
                    raise PrScanError(
                        "--pr-scope-manifest must be a safe path relative to the PR root"
                    )
                manifest = worktree / requested
                if not manifest.is_file():
                    raise PrScanError(
                        f"PR scope manifest does not exist in PR head: {requested.as_posix()}"
                    )

            _result, result_dict = scan_project(
                worktree,
                project_id=f"pr:{target.repository}#{target.number}",
                ci_mode=ci_mode,
                enable_js_ts=enable_js_ts,
                pr_scope_manifest=manifest,
            )

            return {
                "schema_version": "pr_scan_v1",
                "pull_request": asdict(target),
                "execution": {
                    "mode": "temporary_detached_worktree",
                    "read_only": True,
                    "caller_checkout_mutated": False,
                    "pr_scope_manifest": (
                        Path(pr_scope_manifest).as_posix()
                        if pr_scope_manifest is not None
                        else None
                    ),
                },
                "run_result": result_dict,
            }
        finally:
            if materialized:
                cleanup = subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree)],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if cleanup.returncode != 0:
                    # Best-effort prune keeps stale administrative entries from
                    # accumulating; scan results must never pretend cleanup was clean.
                    subprocess.run(
                        ["git", "worktree", "prune"],
                        cwd=root,
                        check=False,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m code_audit.pr_scan",
        description="Scan the exact head tree of a GitHub pull request without changing your checkout.",
    )
    parser.add_argument("pr", help="PR number or canonical GitHub pull-request URL")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--pr-scope-manifest",
        type=Path,
        default=None,
        help="Optional CBSP21 manifest path relative to the PR root.",
    )
    parser.add_argument("--json", action="store_true", dest="json_out")
    parser.add_argument("--no-ci", action="store_false", dest="ci_mode", default=True)
    parser.add_argument("--disable-js-ts", action="store_false", dest="enable_js_ts", default=True)
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT_SECONDS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload = scan_pull_request(
            args.repo_root,
            args.pr,
            ci_mode=args.ci_mode,
            enable_js_ts=args.enable_js_ts,
            pr_scope_manifest=args.pr_scope_manifest,
            timeout=args.timeout,
        )
    except PrScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_out:
        stable_json_dump(payload, sys.stdout, ci_mode=args.ci_mode, indent=2)
    else:
        pr_meta = payload["pull_request"]
        summary = payload["run_result"].get("summary", {})
        count = summary.get("counts", {}).get("findings_total", 0)
        score = summary.get("confidence_score", "?")
        print(
            f"PR #{pr_meta['number']} {pr_meta['title']}\n"
            f"{pr_meta['base_ref']}..{pr_meta['head_ref']} ({pr_meta['head_sha'][:12]})\n"
            f"findings={count} confidence={score}",
            file=sys.stderr,
        )

    # Observation-only v1: successful execution is success regardless of findings.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
