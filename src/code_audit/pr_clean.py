"""PR-CLEAN-001: verify-and-report planning for pull requests.

This increment is deliberately non-mutating with respect to source: it never
edits files, pushes commits, comments on the PR, or declares a pull request
mergeable.  It combines an exact PR head scan, a scan of the PR's verified
merge-base with the captured base-branch tip (its branch point), and a
normalized external assessment to produce a conservative verification report.
The captured base-branch tip is recorded as context but is not the
classification baseline.

Acquisition and cleanup reuse the PR-SCAN v1 contract (``code_audit.pr_scan``):
the head and the captured base commit are fetched into private per-run refs,
both trees are materialized as temporary detached worktrees, and every piece
of Git administrative state created by the run is removed and the removal is
verified.  An unverified cleanup fails the run (exit 2) instead of producing a
report.  The caller's branches, remote-tracking refs and FETCH_HEAD are never
touched.

Assessment claims are evidence, not authority. Automatic confirmation is only
allowed when a claim names a rule_id that the code-analysis suite independently
emits. Claims that cannot be independently tied to a suite rule are routed to
NEEDS_HUMAN_DECISION instead of being guessed at.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sys
import tempfile
from typing import Any

from code_audit.api import scan_project
from code_audit.pr_scan import (
    _SHA_RE,
    MaterializedPr,
    PrScanError,
    PullRequestTarget,
    _cleanup_materialized,
    _materialize_pr_head,
    _require_repo_root,
    _resolve_manifest,
    _run,
    _timeout_arg,
    _validate_timeout,
    resolve_pull_request,
)
from code_audit.utils.json_norm import stable_json_dump

_SCHEMA_VERSION = "pr_clean_plan_v1"
_ASSESSMENT_VERSION = "pr_clean_assessment_v1"
_DEFAULT_TIMEOUT_SECONDS = 30.0
_RUNNER_LOGGER = "code_audit.core.runner"
_HUMAN = "needs_human_decision"


class PrCleanError(RuntimeError):
    """Raised when verify-and-report planning cannot complete safely."""


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    summary: str
    rule_id: str | None = None
    path: str | None = None
    line: int | None = None
    severity: str | None = None
    evidence: str | None = None


def _require_optional_str(raw: Mapping[str, Any], key: str, index: int) -> None:
    value = raw.get(key)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise PrCleanError(f"assessment.claims[{index}].{key} must be non-empty when present")


def _validate_claim(raw: Any, index: int, seen: set[str]) -> None:
    if not isinstance(raw, dict):
        raise PrCleanError(f"assessment.claims[{index}] must be an object")
    cid = raw.get("claim_id")
    if not isinstance(cid, str) or not cid.strip():
        raise PrCleanError(f"assessment.claims[{index}].claim_id must be non-empty")
    if cid in seen:
        raise PrCleanError(f"duplicate assessment claim_id: {cid}")
    seen.add(cid)
    summary = raw.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise PrCleanError(f"assessment.claims[{index}].summary must be non-empty")
    _require_optional_str(raw, "rule_id", index)
    _require_optional_str(raw, "path", index)
    line = raw.get("line")
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise PrCleanError(f"assessment.claims[{index}].line must be a positive integer")


def _load_assessment(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        data = dict(source)
    else:
        path = Path(source)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PrCleanError(f"cannot load assessment {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PrCleanError("assessment must be a JSON object")

    if data.get("schema_version") != _ASSESSMENT_VERSION:
        raise PrCleanError(f"assessment.schema_version must be {_ASSESSMENT_VERSION!r}")
    source_name = data.get("source")
    if not isinstance(source_name, str) or not source_name.strip():
        raise PrCleanError("assessment.source must be a non-empty string")
    claims = data.get("claims")
    if not isinstance(claims, list):
        raise PrCleanError("assessment.claims must be an array")

    seen: set[str] = set()
    for index, raw in enumerate(claims):
        _validate_claim(raw, index, seen)
    return data


def _require_finding(finding: Any, index: int) -> None:
    where = f"scan result findings_raw[{index}]"
    if not isinstance(finding, dict):
        raise PrCleanError(f"{where} must be an object")
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise PrCleanError(f"{where}.fingerprint must be a non-empty string")
    location = finding.get("location")
    if not isinstance(location, dict):
        raise PrCleanError(f"{where}.location must be an object")
    path = location.get("path")
    if not isinstance(path, str) or not path:
        raise PrCleanError(f"{where}.location.path must be a non-empty string")
    for key in ("line_start", "line_end"):
        value = location.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise PrCleanError(f"{where}.location.{key} must be an integer")


def _findings(run_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validated ``findings_raw`` of a run_result_v1; malformed input is an error.

    A missing or malformed findings array is never read as "no findings".
    """
    raw = run_result.get("findings_raw") if isinstance(run_result, Mapping) else None
    if not isinstance(raw, list):
        raise PrCleanError("scan result has no findings_raw array (expected run_result_v1)")
    for index, finding in enumerate(raw):
        _require_finding(finding, index)
    return raw


def _rule_id(finding: Mapping[str, Any]) -> str | None:
    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        rid = metadata.get("rule_id")
        if isinstance(rid, str) and rid:
            return rid
    rid = finding.get("rule_id")
    return rid if isinstance(rid, str) and rid else None


def _path(finding: Mapping[str, Any]) -> str:
    return finding["location"]["path"].replace("\\", "/")


def _covers_line(finding: Mapping[str, Any], line: int) -> bool:
    start = finding["location"].get("line_start")
    if start is None:
        return False
    end = finding["location"].get("line_end") or start
    return start <= line <= end


def _matching_findings(
    claim: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    rule_id = claim.get("rule_id")
    requested_path = claim.get("path")
    requested_path = (
        requested_path.replace("\\", "/") if isinstance(requested_path, str) else None
    )
    return [
        finding
        for finding in findings
        if _rule_id(finding) == rule_id
        and (requested_path is None or _path(finding) == requested_path)
    ]


def _classify_by_identity(
    head_all: Sequence[Mapping[str, Any]],
    head_claimed: Sequence[Mapping[str, Any]],
    base_all: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    """Compare fingerprints; any ambiguity goes to a human, never to pre_existing."""
    base_fps = {f["fingerprint"] for f in base_all}
    head_fps = {f["fingerprint"] for f in head_all}
    claimed_fps = {f["fingerprint"] for f in head_claimed}
    if not claimed_fps - base_fps:
        return "pre_existing", "every matching head finding has the same fingerprint on base"
    if claimed_fps & base_fps:
        return (
            _HUMAN,
            "matches include both pre-existing and new findings; the claim does not "
            "identify which one it refers to",
        )
    if base_fps - head_fps:
        return (
            _HUMAN,
            "a base finding for this rule/path is gone while a new one appeared; "
            "finding identity may have changed",
        )
    return (
        "pr_introduced",
        "claimed finding's fingerprint is absent on base and every base finding "
        "for this rule/path persists on head",
    )


def _classify_matches(
    head_all: Sequence[Mapping[str, Any]],
    head_claimed: Sequence[Mapping[str, Any]],
    base_all: Sequence[Mapping[str, Any]],
) -> tuple[str, str]:
    if not head_all:
        return (
            "unsupported_by_tool",
            "the current suite did not reproduce the claimed rule/path on the PR head",
        )
    if not head_claimed:
        return _HUMAN, "the rule/path is reproduced on head, but not at the claimed line"
    if not base_all:
        return "pr_introduced", "the suite reproduces the claim on head and not on base"
    return _classify_by_identity(head_all, head_claimed, base_all)


def _unlocatable_reason(claim: Mapping[str, Any]) -> str | None:
    rule_id = claim.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        return "claim has no independently checkable rule_id"
    if claim.get("line") is not None and claim.get("path") is None:
        return "claim gives a line without a path; insufficient identification"
    return None


def _verify_claim(
    claim: Mapping[str, Any],
    base_findings: Sequence[Mapping[str, Any]],
    head_findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    head_all: list[Mapping[str, Any]] = []
    head_claimed: list[Mapping[str, Any]] = []
    base_all: list[Mapping[str, Any]] = []
    reason = _unlocatable_reason(claim)
    if reason is not None:
        status = _HUMAN
    else:
        head_all = _matching_findings(claim, head_findings)
        base_all = _matching_findings(claim, base_findings)
        line = claim.get("line")
        head_claimed = (
            head_all if line is None else [f for f in head_all if _covers_line(f, line)]
        )
        status, reason = _classify_matches(head_all, head_claimed, base_all)
    return {
        "claim_id": claim["claim_id"],
        "summary": claim["summary"],
        "source_severity": claim.get("severity"),
        "rule_id": claim.get("rule_id"),
        "path": claim.get("path"),
        "line": claim.get("line"),
        "status": status,
        "reason": reason,
        "head_match_count": len(head_claimed),
        "head_rule_path_match_count": len(head_all),
        "base_match_count": len(base_all),
        "repair_disposition": (
            "human_repair_candidate" if status == "pr_introduced" else "no_automatic_repair"
        ),
    }


def verify_assessment(
    assessment: Mapping[str, Any],
    *,
    base_run_result: Mapping[str, Any],
    head_run_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Conservatively classify assessment claims against independent scans."""
    data = _load_assessment(assessment)
    base_findings = _findings(base_run_result)
    head_findings = _findings(head_run_result)

    verified = [_verify_claim(c, base_findings, head_findings) for c in data["claims"]]
    counts = {
        "pr_introduced": 0,
        "pre_existing": 0,
        "unsupported_by_tool": 0,
        "needs_human_decision": 0,
    }
    for entry in verified:
        counts[entry["status"]] += 1
    return {"source": data["source"], "counts": counts, "claims": verified}


@dataclass(slots=True)
class _Workspace:
    """Git administrative state created by one run (head + base worktrees)."""

    head: MaterializedPr
    base: MaterializedPr


@dataclass(frozen=True, slots=True)
class _Evidence:
    head_result: dict[str, Any]
    base_result: dict[str, Any]
    changed_files: list[str]
    comparison_base_sha: str


def _resolve_merge_base(root: Path, target: PullRequestTarget, *, timeout: float) -> str:
    """The unique merge-base of the captured target-base tip and PR head.

    Both commits were already fetched (and verified) into private refs, so
    their full ancestry is local.  No merge-base, several (criss-cross), or
    malformed output all fail closed.
    """
    problem = f"cannot establish merge-base of {target.base_sha} and {target.head_sha}"
    try:
        out = _run(
            ["git", "merge-base", "--all", target.base_sha, target.head_sha],
            cwd=root,
            timeout=timeout,
        ).stdout.split()
    except PrScanError as exc:
        raise PrCleanError(f"{problem}; refusing to compare") from exc
    if len(out) != 1 or not _SHA_RE.fullmatch(out[0]):
        raise PrCleanError(f"{problem}: expected exactly one commit, got {out!r}")
    return out[0]


def _add_base_worktree(root: Path, ws: _Workspace, sha: str, *, timeout: float) -> None:
    # Mark before the call: a partially-completed add still needs removal.
    ws.base.worktree_registered = True
    _run(["git", "worktree", "add", "--detach", str(ws.base.worktree), sha], cwd=root,
         timeout=timeout)
    actual = _run(["git", "rev-parse", "HEAD"], cwd=ws.base.worktree, timeout=timeout)
    if actual.stdout.strip() != sha:
        raise PrCleanError(
            f"comparison base worktree is at {actual.stdout.strip()!r}, expected {sha}"
        )


def _collect_evidence(
    root: Path,
    target: PullRequestTarget,
    ws: _Workspace,
    pr_scope_manifest: str | Path | None,
    timeout: float,
) -> _Evidence:
    """Materialize exact head + PR merge-base, scan both, and diff them."""
    # Fetches and verifies BOTH head_sha and base_sha into private refs; the
    # caller's remote-tracking refs and FETCH_HEAD are not touched.
    _materialize_pr_head(root, target, ws.head.worktree, timeout=timeout, state=ws.head)
    # Classify against the PR's branch point, not the target branch's tip:
    # later fixes on the target branch must not look PR-introduced.
    comparison_base = _resolve_merge_base(root, target, timeout=timeout)
    _add_base_worktree(root, ws, comparison_base, timeout=timeout)

    manifest = (
        _resolve_manifest(ws.head.worktree, Path(pr_scope_manifest))
        if pr_scope_manifest is not None
        else None
    )
    # Identical analyzer configuration on both sides, including the PR-scope
    # manifest, so a head-only finding cannot be an artefact of scan context.
    ident = f"{target.repository}#{target.number}"
    head_result = _complete_scan(ws.head.worktree, f"pr-head:{ident}", manifest)
    base_result = _complete_scan(ws.base.worktree, f"pr-base:{ident}", manifest)
    changed = _run(
        ["git", "diff", "--name-only", "-z", comparison_base, target.head_sha, "--"],
        cwd=root,
        timeout=timeout,
    ).stdout
    return _Evidence(
        head_result,
        base_result,
        sorted({p for p in changed.split("\0") if p}),
        comparison_base,
    )


class _SkippedAnalyzerProbe(logging.Handler):
    """Collects the runner's "analyzer ... skipped" warnings for one scan."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.skipped: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if message.rstrip().endswith("skipped"):
            self.skipped.append(message)


def _complete_scan(worktree: Path, project_id: str, manifest: Path | None) -> dict[str, Any]:
    """Run one scan and fail closed unless every analyzer completed.

    The runner logs and skips an analyzer that raises or times out; a skipped
    analyzer on either side would make "absent on base" meaningless.
    """
    logger = logging.getLogger(_RUNNER_LOGGER)
    probe = _SkippedAnalyzerProbe()
    old_level = logger.level
    logger.addHandler(probe)
    if logger.getEffectiveLevel() > logging.WARNING:
        logger.setLevel(logging.WARNING)
    try:
        _rr, result = scan_project(
            worktree, project_id=project_id, ci_mode=True, pr_scope_manifest=manifest
        )
    finally:
        logger.removeHandler(probe)
        logger.setLevel(old_level)
    if probe.skipped:
        raise PrCleanError(
            f"{project_id} scan incomplete; refusing to compare: " + "; ".join(probe.skipped)
        )
    _findings(result)  # reject a malformed result before any comparison
    return result


def _cleanup_workspace(root: Path, ws: _Workspace, *, timeout: float) -> dict[str, Any]:
    """Release head and base state; never raises; ``verified`` only if all gone."""
    head = _cleanup_materialized(root, ws.head, timeout=timeout)
    base = _cleanup_materialized(root, ws.base, timeout=timeout)
    return {
        "worktrees_removed": head["worktree_removed"] and base["worktree_removed"],
        "refs_removed": head["refs_removed"] and base["refs_removed"],
        "verified": head["verified"] and base["verified"],
        "errors": head["errors"] + base["errors"],
    }


def _build_report(
    target: PullRequestTarget,
    evidence: _Evidence,
    verification: dict[str, Any],
    cleanup: dict[str, Any],
    pr_scope_manifest: str | Path | None,
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": "verify_and_report_only",
        "merge_decision_performed": False,
        "execution": {
            "source_files_modified": False,
            "caller_checkout_mutated": False,
            "git_admin_metadata": {
                "temporarily_modified": True,
                "fetched_commits": {"head": target.head_sha, "target_base": target.base_sha},
            },
            "cleanup": {k: cleanup[k] for k in ("worktrees_removed", "refs_removed", "verified")},
        },
        "pull_request": _pull_request_block(target, evidence),
        "comparability": {
            "scans_completed": True,
            "analyzers_skipped": 0,
            "identical_scan_configuration": True,
            "pr_scope_manifest_applied_to": ["head", "base"] if pr_scope_manifest else [],
        },
        "scope": {
            "changed_file_count": len(evidence.changed_files),
            "changed_files": evidence.changed_files,
            "pr_scope_manifest": (
                Path(pr_scope_manifest).as_posix() if pr_scope_manifest is not None else None
            ),
        },
        "assessment_verification": verification,
        "repair_plan": _repair_plan(verification),
        "disposition": _disposition(verification["counts"]),
    }


def _pull_request_block(target: PullRequestTarget, evidence: _Evidence) -> dict[str, Any]:
    """PR identity plus the commits compared.

    ``target_base_sha`` (captured tip of the base branch) is context only;
    classification uses ``comparison_base_sha``, the PR's verified merge-base.
    """
    return {
        "number": target.number,
        "url": target.url,
        "title": target.title,
        "repository": target.repository,
        "base_ref": target.base_ref,
        "head_ref": target.head_ref,
        "head_sha": target.head_sha,
        "target_base_sha": target.base_sha,
        "comparison_base_sha": evidence.comparison_base_sha,
        "comparison_strategy": "merge_base",
    }


def _repair_plan(verification: dict[str, Any]) -> list[dict[str, Any]]:
    """Human repair candidates only; nothing is ever applied automatically."""
    return [
        {
            "claim_id": c["claim_id"],
            "summary": c["summary"],
            "rule_id": c["rule_id"],
            "path": c["path"],
            "action": "human_review_and_repair",
            "automatic_apply": False,
        }
        for c in verification["claims"]
        if c["status"] == "pr_introduced"
    ]


def _disposition(counts: dict[str, int]) -> dict[str, Any]:
    return {
        "technical_claims_verified": counts["pr_introduced"],
        "pre_existing": counts["pre_existing"],
        "unsupported": counts["unsupported_by_tool"],
        "needs_human_decision": counts["needs_human_decision"],
        "merge_worthy": None,
        "statement": "No merge-readiness decision is made by PR-CLEAN-001.",
    }


def build_plan(
    repo_root: str | Path,
    pr: str | int,
    *,
    assessment: str | Path | Mapping[str, Any],
    pr_scope_manifest: str | Path | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Build a non-mutating PR remediation plan from independent evidence.

    Raises ``PrCleanError`` when cleanup of the run's Git administrative state
    cannot be verified; a primary failure carries any cleanup failure as a note.
    """
    timeout = _validate_timeout(timeout)
    # Validate the assessment before touching Git at all.
    data = _load_assessment(assessment)
    root = _require_repo_root(Path(repo_root), timeout=timeout)
    target = resolve_pull_request(root, pr, timeout=timeout)

    with tempfile.TemporaryDirectory(prefix="code-audit-pr-clean-") as temp_dir:
        ws = _Workspace(
            head=MaterializedPr(worktree=Path(temp_dir) / "head"),
            base=MaterializedPr(worktree=Path(temp_dir) / "base"),
        )
        try:
            evidence = _collect_evidence(root, target, ws, pr_scope_manifest, timeout)
        except BaseException as exc:
            cleanup = _cleanup_workspace(root, ws, timeout=timeout)
            if not cleanup["verified"]:
                exc.add_note(
                    "pr_clean cleanup also failed; stale Git metadata may remain: "
                    + "; ".join(cleanup["errors"])
                )
            raise
        cleanup = _cleanup_workspace(root, ws, timeout=timeout)
        if not cleanup["verified"]:
            raise PrCleanError(
                "scans completed but cleanup could not be verified; refusing to report. "
                "Stale Git metadata may remain: " + "; ".join(cleanup["errors"])
            )

    verification = verify_assessment(
        data,
        base_run_result=evidence.base_result,
        head_run_result=evidence.head_result,
    )
    return _build_report(target, evidence, verification, cleanup, pr_scope_manifest)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m code_audit.pr_clean",
        description="Verify a PR assessment and emit a non-mutating remediation plan.",
    )
    parser.add_argument("pr", help="PR number or canonical GitHub pull-request URL")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--pr-scope-manifest", type=Path, default=None)
    parser.add_argument("--json", action="store_true", dest="json_out")
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
        report = build_plan(
            args.repo_root,
            args.pr,
            assessment=args.assessment,
            pr_scope_manifest=args.pr_scope_manifest,
            timeout=args.timeout,
        )
    except (PrCleanError, PrScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(f"note: {note}", file=sys.stderr)
        return 2

    if args.json_out:
        stable_json_dump(report, sys.stdout, ci_mode=True, indent=2)
    else:
        pr = report["pull_request"]
        counts = report["assessment_verification"]["counts"]
        print(f"PR #{pr['number']} — {pr['title']}", file=sys.stderr)
        print(
            "assessment: "
            f"introduced={counts['pr_introduced']} "
            f"pre_existing={counts['pre_existing']} "
            f"unsupported={counts['unsupported_by_tool']} "
            f"needs_human={counts['needs_human_decision']}",
            file=sys.stderr,
        )
        print("No files changed. No merge-readiness decision made.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
