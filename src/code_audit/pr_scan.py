"""Pull-request scan orchestration that leaves the caller's checkout untouched.

This module makes a GitHub pull request a first-class scan target without
mutating the caller's checkout.  It resolves PR metadata with ``gh``, fetches
the exact PR head *and* the exact captured base commit into a private,
per-run ref namespace, materializes the head in a temporary detached
worktree, and runs the existing ``scan_project`` pipeline against that tree.

Mutation guarantees (reported explicitly under ``execution`` rather than as a
single ``read_only`` boolean):

* target source files: never modified
* caller checkout: branch, index and tracked files unchanged
* Git administrative metadata: *temporarily* modified (fetched objects,
  ``refs/code-audit/run/<token>/...`` refs, one worktree registration)
* cleanup: the worktree registration and the private refs are removed and
  the removal is verified; an unverified cleanup fails the scan (exit 2)
  instead of reporting success

V1 is deliberately observation-only:

* no PR comments or reviews
* no merge/update actions
* no new blocking policy
* no checkout/branch switch in the caller's working tree

Usage::

    python -m code_audit.pr_scan 296 --repo-root . --json
    python -m code_audit.pr_scan https://github.com/OWNER/REPO/pull/296 --repo-root .

A URL target must name the same repository as ``--repo-root``; a mismatch is
refused rather than silently scanning the same-numbered PR of the local repo.

An optional ``--pr-scope-manifest`` path is interpreted relative to the PR
worktree (and must resolve inside it) and activates the existing ``pr_scope``
analyzer during the scan.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any
import uuid

from code_audit.api import scan_project
from code_audit.utils.json_norm import stable_json_dump

_DEFAULT_TIMEOUT_SECONDS = 30.0
_PR_URL_RE = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)"
    r"/(?P<repo>[A-Za-z0-9._-]+)/pull/(?P<number>[1-9][0-9]*)(?:/.*)?$"
)
_REMOTE_REPO_RE = re.compile(r"github\.com[:/](?P<owner>[^/:]+)/(?P<repo>[^/]+?)(?:\.git)?/*$")
_SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


class PrScanError(RuntimeError):
    """Raised when PR resolution/materialization cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class PrSpec:
    """A parsed PR target.  ``repository`` is set only for URL input."""

    number: int
    repository: str | None = None


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


@dataclass(slots=True)
class MaterializedPr:
    """Git administrative state created by one run, tracked for verified cleanup."""

    worktree: Path
    ref_prefix: str = ""
    head_ref_local: str = ""
    base_ref_local: str = ""
    refs_created: list[str] = field(default_factory=list)
    worktree_registered: bool = False


@dataclass(frozen=True, slots=True)
class PrScanOptions:
    """Scan behaviour for ``scan_pull_request``."""

    ci_mode: bool = True
    enable_js_ts: bool = True
    pr_scope_manifest: str | Path | None = None
    timeout: float = _DEFAULT_TIMEOUT_SECONDS


def _validate_timeout(timeout: Any) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError) as exc:
        raise PrScanError(f"timeout must be a number of seconds, got {timeout!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise PrScanError(
            f"timeout must be a finite positive number of seconds, got {timeout!r}"
        )
    return value


def _same_repo(a: str, b: str) -> bool:
    # GitHub owner/repo names are case-insensitive.
    return a.casefold() == b.casefold()


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
    except (OSError, ValueError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise PrScanError(f"command failed to execute: {' '.join(args)}: {exc}") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise PrScanError(
            f"command failed ({completed.returncode}): {' '.join(args)}"
            + (f": {stderr}" if stderr else "")
        )
    return completed


def _parse_pr_target(value: str) -> PrSpec:
    raw = value.strip()
    if raw.isascii() and raw.isdigit() and int(raw) > 0:
        return PrSpec(number=int(raw))
    match = _PR_URL_RE.fullmatch(raw)
    if match:
        repo = match.group("repo")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        return PrSpec(
            number=int(match.group("number")),
            repository=f"{match.group('owner')}/{repo}",
        )
    raise PrScanError(
        "PR target must be a positive pull-request number or a canonical "
        "https://github.com/OWNER/REPO/pull/NUMBER URL"
    )


def _parse_pr_number(value: str) -> int:
    """PR number only.  Callers that accept URLs must use ``_parse_pr_target``."""
    return _parse_pr_target(value).number


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


def _origin_repo_name(root: Path, *, timeout: float) -> str:
    url = _run(
        ["git", "remote", "get-url", "origin"], cwd=root, timeout=timeout
    ).stdout.strip()
    match = _REMOTE_REPO_RE.search(url)
    if not match:
        raise PrScanError(f"origin remote is not a GitHub repository URL: {url!r}")
    return f"{match.group('owner')}/{match.group('repo')}"


def _resolve_repository(root: Path, spec: PrSpec, *, timeout: float) -> str:
    """Return the checkout's GitHub repository, failing closed on any mismatch.

    The repository named by a PR URL, the repository ``gh`` resolves for the
    checkout, and ``origin`` (where commits are fetched from) must all agree.
    """
    repository = _repo_name(root, timeout=timeout)
    if spec.repository is not None and not _same_repo(spec.repository, repository):
        raise PrScanError(
            f"PR URL names repository {spec.repository} but --repo-root is a checkout "
            f"of {repository}; refusing to scan PR #{spec.number} of a different repository"
        )
    origin_repository = _origin_repo_name(root, timeout=timeout)
    if not _same_repo(repository, origin_repository):
        raise PrScanError(
            f"gh resolves this checkout to {repository} but origin is "
            f"{origin_repository}; refusing to fetch commits from a different repository"
        )
    return repository


_PR_METADATA_FIELDS: dict[str, type] = {
    "number": int,
    "url": str,
    "title": str,
    "baseRefName": str,
    "baseRefOid": str,
    "headRefName": str,
    "headRefOid": str,
}


def _fetch_pr_metadata(
    root: Path, repository: str, number: int, *, timeout: float
) -> dict[str, Any]:
    """Fetch PR metadata with ``gh`` and validate field presence and types."""
    raw = _run(
        [
            "gh",
            "pr",
            "view",
            str(number),
            "--repo",
            repository,
            "--json",
            ",".join(_PR_METADATA_FIELDS),
        ],
        cwd=root,
        timeout=timeout,
    ).stdout
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PrScanError(f"gh returned invalid PR metadata JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PrScanError("gh returned PR metadata that is not a JSON object")

    for key, expected_type in _PR_METADATA_FIELDS.items():
        value = data.get(key)
        if (
            not isinstance(value, expected_type)
            or isinstance(value, bool)
            or (isinstance(value, str) and not value)
        ):
            raise PrScanError(f"gh PR metadata missing/invalid field: {key}")
    return data


def _check_metadata_identity(data: dict[str, Any], repository: str, number: int) -> None:
    """Verify GitHub answered for exactly the PR that was requested."""
    if data["number"] != number:
        raise PrScanError(f"gh returned PR #{data['number']} when PR #{number} was requested")
    expected_url = f"https://github.com/{repository}/pull/{number}"
    if not _same_repo(data["url"], expected_url):
        raise PrScanError(
            f"gh returned PR URL {data['url']!r}; expected canonical {expected_url!r}"
        )
    for key in ("baseRefOid", "headRefOid"):
        if not _SHA_RE.fullmatch(data[key]):
            raise PrScanError(f"gh PR metadata field {key} is not a full commit SHA")


def resolve_pull_request(
    repo_root: Path,
    pr: str | int,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> PullRequestTarget:
    """Resolve immutable PR refs from GitHub using the authenticated ``gh`` CLI.

    Fails closed when the PR cannot be attributed to the local repository: a
    URL naming another repository, ``gh``'s repository differing from
    ``origin`` (the remote commits are fetched from), or GitHub returning
    metadata for a different PR number or repository.
    """
    timeout = _validate_timeout(timeout)
    root = _require_repo_root(repo_root, timeout=timeout)
    spec = _parse_pr_target(str(pr))
    repository = _resolve_repository(root, spec, timeout=timeout)
    data = _fetch_pr_metadata(root, repository, spec.number, timeout=timeout)
    _check_metadata_identity(data, repository, spec.number)

    return PullRequestTarget(
        number=spec.number,
        url=data["url"],
        title=data["title"],
        repository=repository,
        base_ref=data["baseRefName"],
        base_sha=data["baseRefOid"],
        head_ref=data["headRefName"],
        head_sha=data["headRefOid"],
    )


@dataclass(frozen=True, slots=True)
class _RefFetch:
    """One commit to fetch from origin into a private ref and verify."""

    source: str
    local_ref: str
    expected_sha: str
    label: str


def _fetch_and_verify(
    root: Path, state: MaterializedPr, fetch: _RefFetch, *, timeout: float
) -> None:
    # Record before fetching: a fetch that times out mid-way may still have
    # written the ref, and cleanup must cover it.
    state.refs_created.append(fetch.local_ref)
    _run(
        [
            "git",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "origin",
            f"+{fetch.source}:{fetch.local_ref}",
        ],
        cwd=root,
        timeout=timeout,
    )
    resolved = _run(
        ["git", "rev-parse", "--verify", f"{fetch.local_ref}^{{commit}}"],
        cwd=root,
        timeout=timeout,
    ).stdout.strip()
    if resolved != fetch.expected_sha:
        raise PrScanError(
            f"PR {fetch.label} mismatch while materializing: "
            f"GitHub reported {fetch.expected_sha}, fetched {resolved}"
        )


def _materialize_pr_head(
    root: Path,
    target: PullRequestTarget,
    worktree: Path,
    *,
    timeout: float,
    state: MaterializedPr | None = None,
) -> MaterializedPr:
    """Fetch the exact captured head *and* base commits; add a detached worktree.

    Refs live under a per-run ``refs/code-audit/run/<token>/`` namespace so
    concurrent runs never collide and the caller's branches, remote-tracking
    refs and FETCH_HEAD are untouched.  Pass ``state`` to have it populated
    incrementally so the caller can clean up after a partial failure; then
    release everything with ``_cleanup_materialized``.
    """
    if state is None:
        state = MaterializedPr(worktree=worktree)
    state.worktree = worktree
    state.ref_prefix = f"refs/code-audit/run/{uuid.uuid4().hex}"
    state.head_ref_local = f"{state.ref_prefix}/pr-{target.number}/head"
    state.base_ref_local = f"{state.ref_prefix}/pr-{target.number}/base"

    # GitHub exposes PR heads under refs/pull/<n>/head even for fork PRs.
    head = _RefFetch(
        f"refs/pull/{target.number}/head", state.head_ref_local, target.head_sha, "head"
    )
    # Materialize the *captured* base commit rather than the base branch's
    # current tip, so base/head comparisons are attributable to the exact
    # pair GitHub reported.
    base = _RefFetch(target.base_sha, state.base_ref_local, target.base_sha, "base")
    _fetch_and_verify(root, state, head, timeout=timeout)
    _fetch_and_verify(root, state, base, timeout=timeout)

    # Mark before the call: a partially-completed add still needs removal.
    state.worktree_registered = True
    _run(
        ["git", "worktree", "add", "--detach", str(worktree), target.head_sha],
        cwd=root,
        timeout=timeout,
    )
    return state


def _remove_worktree(
    root: Path, state: MaterializedPr, errors: list[str], *, timeout: float
) -> bool:
    """Remove the run's worktree registration; True only if verified gone."""
    if not state.worktree_registered:
        return True
    try:
        _run(
            ["git", "worktree", "remove", "--force", str(state.worktree)],
            cwd=root,
            timeout=timeout,
        )
    except PrScanError as exc:
        errors.append(str(exc))
        try:
            _run(["git", "worktree", "prune"], cwd=root, timeout=timeout)
        except PrScanError as prune_exc:
            errors.append(str(prune_exc))
    try:
        listing = _run(["git", "worktree", "list", "--porcelain"], cwd=root, timeout=timeout).stdout
    except PrScanError as exc:
        errors.append(f"could not verify worktree removal: {exc}")
        return False
    registered = {
        Path(line[len("worktree "):]).resolve()
        for line in listing.splitlines()
        if line.startswith("worktree ")
    }
    if state.worktree.resolve() in registered:
        errors.append(f"worktree still registered after cleanup: {state.worktree}")
        return False
    return True


def _remove_private_refs(
    root: Path, state: MaterializedPr, errors: list[str], *, timeout: float
) -> list[str]:
    """Delete the run's private refs; return any that verifiably remain."""
    if not state.refs_created:
        return []
    for ref in state.refs_created:
        # A ref that was never written makes update-ref fail; the
        # for-each-ref listing below is the authority on what remains.
        try:
            _run(["git", "update-ref", "-d", ref], cwd=root, timeout=timeout)
        except PrScanError:
            pass
    try:
        listing = _run(
            ["git", "for-each-ref", "--format=%(refname)", state.ref_prefix],
            cwd=root,
            timeout=timeout,
        ).stdout
    except PrScanError as exc:
        errors.append(f"could not verify ref removal: {exc}")
        return list(state.refs_created)
    remaining = [line for line in listing.splitlines() if line]
    if remaining:
        errors.append(f"private refs still present after cleanup: {remaining}")
    return remaining


def _cleanup_materialized(
    root: Path, state: MaterializedPr, *, timeout: float
) -> dict[str, Any]:
    """Remove the run's worktree registration and private refs, then verify.

    Never raises.  The returned report's ``verified`` flag is False whenever
    any administrative state created by the run is still present (or its
    absence could not be confirmed).
    """
    errors: list[str] = []
    worktree_removed = _remove_worktree(root, state, errors, timeout=timeout)
    refs_remaining = _remove_private_refs(root, state, errors, timeout=timeout)
    return {
        "worktree_removed": worktree_removed,
        "refs_removed": not refs_remaining,
        "verified": worktree_removed and not refs_remaining,
        "errors": errors,
    }


def _resolve_manifest(worktree: Path, requested: Path) -> Path:
    if requested.is_absolute() or requested.drive or ".." in requested.parts:
        raise PrScanError("--pr-scope-manifest must be a safe path relative to the PR root")
    root_resolved = worktree.resolve()
    candidate = (worktree / requested).resolve()
    # The lexical check above is not sufficient: a symlink committed in the PR
    # tree can point anywhere.  Containment is enforced on the resolved path.
    if not candidate.is_relative_to(root_resolved):
        raise PrScanError(
            "--pr-scope-manifest resolves outside the PR worktree: "
            f"{requested.as_posix()}"
        )
    if not candidate.is_file():
        raise PrScanError(
            f"PR scope manifest does not exist in PR head: {requested.as_posix()}"
        )
    return candidate


def _scan_materialized(
    root: Path, target: PullRequestTarget, state: MaterializedPr, opts: PrScanOptions
) -> dict[str, Any]:
    """Materialize the PR into ``state.worktree`` and run the scan pipeline."""
    _materialize_pr_head(root, target, state.worktree, timeout=opts.timeout, state=state)
    manifest: Path | None = None
    if opts.pr_scope_manifest is not None:
        manifest = _resolve_manifest(state.worktree, Path(opts.pr_scope_manifest))
    _result, result_dict = scan_project(
        state.worktree,
        project_id=f"pr:{target.repository}#{target.number}",
        ci_mode=opts.ci_mode,
        enable_js_ts=opts.enable_js_ts,
        pr_scope_manifest=manifest,
    )
    return result_dict


def _build_payload(
    target: PullRequestTarget,
    state: MaterializedPr,
    report: dict[str, Any],
    opts: PrScanOptions,
    result_dict: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "pr_scan_v1",
        "pull_request": asdict(target),
        "execution": {
            "mode": "temporary_detached_worktree",
            "source_files_modified": False,
            "caller_checkout_mutated": False,
            "git_admin_metadata": {
                "temporarily_modified": True,
                "fetched_commits": {"head": target.head_sha, "base": target.base_sha},
                "private_ref_count": len(state.refs_created),
                "worktree_registered": state.worktree_registered,
            },
            "cleanup": {
                "worktree_removed": report["worktree_removed"],
                "refs_removed": report["refs_removed"],
                "verified": report["verified"],
            },
            "pr_scope_manifest": (
                Path(opts.pr_scope_manifest).as_posix()
                if opts.pr_scope_manifest is not None
                else None
            ),
        },
        "run_result": result_dict,
    }


def scan_pull_request(
    repo_root: str | Path,
    pr: str | int,
    options: PrScanOptions | None = None,
) -> dict[str, Any]:
    """Scan the exact head tree of a GitHub pull request.

    The caller's working tree is never checked out or reset.  The temporary
    worktree and private refs are removed before return/raise and the removal
    is verified; if it cannot be verified this raises ``PrScanError`` instead
    of returning a result.
    """
    opts = options if options is not None else PrScanOptions()
    opts = replace(opts, timeout=_validate_timeout(opts.timeout))
    root = _require_repo_root(Path(repo_root), timeout=opts.timeout)
    target = resolve_pull_request(root, pr, timeout=opts.timeout)

    with tempfile.TemporaryDirectory(prefix="code-audit-pr-scan-") as temp_dir:
        state = MaterializedPr(worktree=Path(temp_dir) / "worktree")
        try:
            result_dict = _scan_materialized(root, target, state, opts)
        except BaseException as exc:
            report = _cleanup_materialized(root, state, timeout=opts.timeout)
            if not report["verified"]:
                # Never mask the primary failure, but never hide cleanup either.
                exc.add_note(
                    "pr_scan cleanup also failed; stale Git metadata may remain: "
                    + "; ".join(report["errors"])
                )
            raise

        report = _cleanup_materialized(root, state, timeout=opts.timeout)
        if not report["verified"]:
            raise PrScanError(
                "scan completed but cleanup could not be verified; refusing to report "
                "success. Stale Git metadata may remain: " + "; ".join(report["errors"])
            )

    return _build_payload(target, state, report, opts, result_dict)


def _timeout_arg(value: str) -> float:
    try:
        return _validate_timeout(value)
    except PrScanError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m code_audit.pr_scan",
        description=(
            "Scan the exact head tree of a GitHub pull request "
            "without changing your checkout."
        ),
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
    parser.add_argument(
        "--timeout",
        type=_timeout_arg,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help="Per-command timeout in seconds (finite, > 0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload = scan_pull_request(
            args.repo_root,
            args.pr,
            PrScanOptions(
                ci_mode=args.ci_mode,
                enable_js_ts=args.enable_js_ts,
                pr_scope_manifest=args.pr_scope_manifest,
                timeout=args.timeout,
            ),
        )
    except PrScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(f"note: {note}", file=sys.stderr)
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
