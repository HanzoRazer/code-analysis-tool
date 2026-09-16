"""PR-CLEAN-001: verify-and-report planning for pull requests.

This increment is deliberately non-mutating. It combines an exact PR scan,
a baseline scan of the PR base SHA, and a normalized external assessment to
produce a conservative verification report. It never edits files, pushes
commits, comments on the PR, or declares a pull request mergeable.

Assessment claims are evidence, not authority. Automatic confirmation is only
allowed when a claim names a rule_id that the code-analysis suite independently
emits. Claims that cannot be independently tied to a suite rule are routed to
NEEDS_HUMAN_DECISION instead of being guessed at.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from code_audit.api import scan_project
from code_audit.pr_scan import (
    PrScanError,
    _materialize_pr_head,
    _require_repo_root,
    _run,
    resolve_pull_request,
)
from code_audit.utils.json_norm import stable_json_dump

_SCHEMA_VERSION = "pr_clean_plan_v1"
_ASSESSMENT_VERSION = "pr_clean_assessment_v1"


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


def _load_assessment(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        data = dict(source)
    else:
        path = Path(source)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PrCleanError(f"cannot load assessment {path}: {exc}") from exc

    if data.get("schema_version") != _ASSESSMENT_VERSION:
        raise PrCleanError(
            f"assessment.schema_version must be {_ASSESSMENT_VERSION!r}"
        )
    source_name = data.get("source")
    if not isinstance(source_name, str) or not source_name.strip():
        raise PrCleanError("assessment.source must be a non-empty string")
    claims = data.get("claims")
    if not isinstance(claims, list):
        raise PrCleanError("assessment.claims must be an array")

    seen: set[str] = set()
    for index, raw in enumerate(claims):
        if not isinstance(raw, dict):
            raise PrCleanError(f"assessment.claims[{index}] must be an object")
        cid = raw.get("claim_id")
        summary = raw.get("summary")
        if not isinstance(cid, str) or not cid.strip():
            raise PrCleanError(f"assessment.claims[{index}].claim_id must be non-empty")
        if cid in seen:
            raise PrCleanError(f"duplicate assessment claim_id: {cid}")
        seen.add(cid)
        if not isinstance(summary, str) or not summary.strip():
            raise PrCleanError(f"assessment.claims[{index}].summary must be non-empty")
        rule_id = raw.get("rule_id")
        if rule_id is not None and (not isinstance(rule_id, str) or not rule_id.strip()):
            raise PrCleanError(f"assessment.claims[{index}].rule_id must be non-empty when present")
        path = raw.get("path")
        if path is not None and (not isinstance(path, str) or not path.strip()):
            raise PrCleanError(f"assessment.claims[{index}].path must be non-empty when present")
        line = raw.get("line")
        if line is not None and (not isinstance(line, int) or line < 1):
            raise PrCleanError(f"assessment.claims[{index}].line must be a positive integer")
    return data


def _findings(run_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = run_result.get("findings", [])
    return [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []


def _rule_id(finding: Mapping[str, Any]) -> str | None:
    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        rid = metadata.get("rule_id")
        if isinstance(rid, str) and rid:
            return rid
    rid = finding.get("rule_id")
    return rid if isinstance(rid, str) and rid else None


def _path(finding: Mapping[str, Any]) -> str | None:
    location = finding.get("location")
    if isinstance(location, dict):
        path = location.get("path")
        if isinstance(path, str) and path:
            return path.replace("\\", "/")
    return None


def _fingerprint(finding: Mapping[str, Any]) -> str | None:
    value = finding.get("fingerprint") or finding.get("finding_id")
    return value if isinstance(value, str) and value else None


def _matching_findings(
    claim: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    rule_id = claim.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        return []
    requested_path = claim.get("path")
    requested_path = (
        requested_path.replace("\\", "/")
        if isinstance(requested_path, str)
        else None
    )
    matches = []
    for finding in findings:
        if _rule_id(finding) != rule_id:
            continue
        if requested_path is not None and _path(finding) != requested_path:
            continue
        matches.append(finding)
    return matches


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

    verified: list[dict[str, Any]] = []
    counts = {
        "pr_introduced": 0,
        "pre_existing": 0,
        "unsupported_by_tool": 0,
        "needs_human_decision": 0,
    }

    for claim in data["claims"]:
        rule_id = claim.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            status = "needs_human_decision"
            reason = "claim has no independently checkable rule_id"
            head_matches: list[Mapping[str, Any]] = []
            base_matches: list[Mapping[str, Any]] = []
        else:
            head_matches = _matching_findings(claim, head_findings)
            base_matches = _matching_findings(claim, base_findings)
            if not head_matches:
                status = "unsupported_by_tool"
                reason = "the current suite did not reproduce the claimed rule/path on the PR head"
            else:
                head_fps = {_fingerprint(f) for f in head_matches if _fingerprint(f)}
                base_fps = {_fingerprint(f) for f in base_matches if _fingerprint(f)}
                if base_matches and (not head_fps or not base_fps or head_fps & base_fps):
                    status = "pre_existing"
                    reason = "the independently reproduced finding is also present on the PR base"
                elif base_matches:
                    # Rule/path existed on base but identity changed. Conservatively
                    # avoid claiming the PR introduced it without human adjudication.
                    status = "needs_human_decision"
                    reason = "same rule/path exists on base but finding identity changed"
                else:
                    status = "pr_introduced"
                    reason = "the suite reproduces the claim on head and not on base"

        counts[status] += 1
        verified.append(
            {
                "claim_id": claim["claim_id"],
                "summary": claim["summary"],
                "source_severity": claim.get("severity"),
                "rule_id": claim.get("rule_id"),
                "path": claim.get("path"),
                "status": status,
                "reason": reason,
                "head_match_count": len(head_matches),
                "base_match_count": len(base_matches),
                "repair_disposition": (
                    "human_repair_candidate"
                    if status == "pr_introduced"
                    else "no_automatic_repair"
                ),
            }
        )

    return {
        "source": data["source"],
        "counts": counts,
        "claims": verified,
    }


def _scan_base(
    root: Path,
    *,
    base_sha: str,
    repository: str,
    pr_number: int,
    timeout: float,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="code-audit-pr-clean-base-") as temp_dir:
        worktree = Path(temp_dir) / "base"
        materialized = False
        try:
            _run(["git", "worktree", "add", "--detach", str(worktree), base_sha], cwd=root, timeout=timeout)
            materialized = True
            _result, result_dict = scan_project(
                worktree,
                project_id=f"pr-base:{repository}#{pr_number}",
                ci_mode=True,
            )
            return result_dict
        finally:
            if materialized:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree)],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )


def build_plan(
    repo_root: str | Path,
    pr: str | int,
    *,
    assessment: str | Path | Mapping[str, Any],
    pr_scope_manifest: str | Path | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Build a non-mutating PR remediation plan from independent evidence."""
    root = _require_repo_root(Path(repo_root), timeout=timeout)
    target = resolve_pull_request(root, pr, timeout=timeout)

    # Ensure the exact base and PR head are locally available before either scan.
    _run(["git", "fetch", "--no-tags", "origin", target.base_ref], cwd=root, timeout=timeout)

    with tempfile.TemporaryDirectory(prefix="code-audit-pr-clean-head-") as temp_dir:
        head_worktree = Path(temp_dir) / "head"
        materialized = False
        try:
            _materialize_pr_head(root, target, head_worktree, timeout=timeout)
            materialized = True
            manifest: Path | None = None
            if pr_scope_manifest is not None:
                relative = Path(pr_scope_manifest)
                if relative.is_absolute() or ".." in relative.parts:
                    raise PrCleanError("pr_scope_manifest must be relative to the PR root")
                manifest = head_worktree / relative
                if not manifest.is_file():
                    raise PrCleanError(f"PR scope manifest not found in head: {relative.as_posix()}")
            _head_result, head_result = scan_project(
                head_worktree,
                project_id=f"pr-head:{target.repository}#{target.number}",
                ci_mode=True,
                pr_scope_manifest=manifest,
            )
        finally:
            if materialized:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(head_worktree)],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )

    base_result = _scan_base(
        root,
        base_sha=target.base_sha,
        repository=target.repository,
        pr_number=target.number,
        timeout=timeout,
    )
    verification = verify_assessment(
        _load_assessment(assessment),
        base_run_result=base_result,
        head_run_result=head_result,
    )

    changed = _run(
        ["git", "diff", "--name-only", "-z", target.base_sha, target.head_sha, "--"],
        cwd=root,
        timeout=timeout,
    ).stdout
    changed_files = sorted({p for p in changed.split("\0") if p})

    repair_candidates = [
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

    return {
        "schema_version": _SCHEMA_VERSION,
        "mode": "verify_and_report_only",
        "mutations_performed": False,
        "merge_decision_performed": False,
        "pull_request": {
            "number": target.number,
            "url": target.url,
            "title": target.title,
            "repository": target.repository,
            "base_ref": target.base_ref,
            "base_sha": target.base_sha,
            "head_ref": target.head_ref,
            "head_sha": target.head_sha,
        },
        "scope": {
            "changed_file_count": len(changed_files),
            "changed_files": changed_files,
            "pr_scope_manifest": Path(pr_scope_manifest).as_posix() if pr_scope_manifest else None,
        },
        "assessment_verification": verification,
        "repair_plan": repair_candidates,
        "disposition": {
            "technical_claims_verified": verification["counts"]["pr_introduced"],
            "pre_existing": verification["counts"]["pre_existing"],
            "unsupported": verification["counts"]["unsupported_by_tool"],
            "needs_human_decision": verification["counts"]["needs_human_decision"],
            "merge_worthy": None,
            "statement": "No merge-readiness decision is made by PR-CLEAN-001.",
        },
    }


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
    parser.add_argument("--timeout", type=float, default=30.0)
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
