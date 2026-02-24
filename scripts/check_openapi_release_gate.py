from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from code_audit.web_api.openapi_diff import apply_allowlist_policy, diff_openapi_core
from code_audit.web_api.openapi_normalize import normalize_openapi

from scripts.release_gate_json import (
    build_gate_failure_json,
    emit_gate_failure_human,
    emit_gate_failure_json,
    is_ci_true,
)


ROOT = Path(__file__).resolve().parents[1]
CURRENT_OPENAPI = ROOT / "docs" / "openapi.json"
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"
OUT_DIR = ROOT / "dist"
OUT_REPORT = OUT_DIR / "openapi_diff_report.json"
OUT_GATE_RESULT = OUT_DIR / "openapi_release_gate_result.json"
OPENAPI_REPO_PATH = "docs/openapi.json"

DIST_BEFORE_OPENAPI = OUT_DIR / "openapi_before.json"
DIST_AFTER_OPENAPI = OUT_DIR / "openapi_after.json"

CLASSIFIER_FILES = [
    ROOT / "src" / "code_audit" / "web_api" / "openapi_normalize.py",
    ROOT / "src" / "code_audit" / "web_api" / "openapi_diff.py",
    ROOT / "src" / "code_audit" / "web_api" / "schema_semver.py",
]


TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _issue(kind: str, path: str, expected: Any, got: Any, details: Any = None) -> Dict[str, Any]:
    """Build a structured issue dict for gate failure details."""
    d: Dict[str, Any] = {"kind": kind, "path": path, "expected": expected, "got": got}
    if details is not None:
        d["details"] = details
    return d


def _emit_and_exit(issues: List[Dict[str, Any]], json_mode: bool) -> int:
    """Build gate failure JSON, write to dist, emit, and return exit code 1."""
    result = build_gate_failure_json(
        kind="openapi_release_gate_failed",
        path="dist/*",
        expected="clean gate",
        got=f"{len(issues)} issue(s)",
        details=issues,
    )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_GATE_RESULT.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if json_mode:
        emit_gate_failure_json(result)
    else:
        emit_gate_failure_human(result, prefix="openapi-release-gate")
    return 1


def _load_json_or_issue(
    path: Path, label: str, issues: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Load a JSON file, appending an issue on failure."""
    if not path.exists():
        issues.append(_issue("missing_file", str(path), "present", "missing"))
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        issues.append(_issue("invalid_json", str(path), "valid JSON", str(e)))
        return None


def _run_git(args: list[str]) -> str:
    p = subprocess.run(
        ["git", *args],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def _current_tag_from_env() -> str:
    tag = os.environ.get("GITHUB_REF_NAME") or ""
    tag = tag.strip()
    if not tag:
        raise RuntimeError("GITHUB_REF_NAME is not set; this gate is intended for tag builds.")
    return tag


def _parse_tag(tag: str) -> tuple[int, int, int]:
    m = TAG_RE.match(tag)
    if not m:
        raise RuntimeError(f"Tag '{tag}' does not match vX.Y.Z.")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _list_tags_desc() -> list[str]:
    out = _run_git(["tag", "--list", "v*", "--sort=-v:refname"])
    tags = [t.strip() for t in out.splitlines() if t.strip()]
    return tags


def _find_previous_tag(current: str) -> Optional[str]:
    tags = _list_tags_desc()
    if current not in tags:
        raise RuntimeError(f"Current tag '{current}' not found in git tag list.")
    idx = tags.index(current)
    if idx == len(tags) - 1:
        return None
    return tags[idx + 1]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_openapi_at_tag(tag: str) -> Dict[str, Any]:
    raw = _run_git(["show", f"{tag}:{OPENAPI_REPO_PATH}"])
    return json.loads(raw)


def _load_openapi_raw_at_tag(tag: str) -> bytes:
    raw = _run_git(["show", f"{tag}:{OPENAPI_REPO_PATH}"])
    return raw.encode("utf-8")


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _summarize_report(report: Dict[str, Any]) -> str:
    s = report.get("summary") or {}
    return (
        f"breaking={report.get('breaking')} "
        f"breaking_count={s.get('breaking_count')} "
        f"unknown_count={s.get('unknown_count')} "
        f"non_breaking_count={s.get('non_breaking_count')}"
    )


def main() -> int:
    json_mode = "--json" in sys.argv
    issues: List[Dict[str, Any]] = []

    current_tag = _current_tag_from_env()
    cur_major, cur_minor, cur_patch = _parse_tag(current_tag)

    if not CURRENT_OPENAPI.exists():
        issues.append(_issue("missing_file", str(CURRENT_OPENAPI), "present", "missing"))
        return _emit_and_exit(issues, json_mode)

    policy = _load_json_or_issue(POLICY_PATH, "openapi_breaking_policy.json", issues)
    if policy is None:
        return _emit_and_exit(issues, json_mode)

    prev = _find_previous_tag(current_tag)
    if prev is None:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        report = {
            "version": 1,
            "breaking": False,
            "summary": {"breaking_count": 0, "non_breaking_count": 0, "unknown_count": 0},
            "breaking_changes": [],
            "non_breaking_changes": [],
            "unknown_changes": [],
            "notes": f"First release tag {current_tag}; no previous tag found.",
        }
        OUT_REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[openapi-release-gate] {current_tag}: first tag, no diff baseline. OK.")
        return 0

    prev_major, prev_minor, prev_patch = _parse_tag(prev)

    try:
        before_doc = _load_openapi_at_tag(prev)
    except Exception as e:
        issues.append(_issue("snapshot_load_failed", f"git:{prev}:{OPENAPI_REPO_PATH}", "loadable", str(e)))
        return _emit_and_exit(issues, json_mode)

    after_doc = _load_json(CURRENT_OPENAPI)
    policy_sha = _sha256_file(POLICY_PATH)

    # Write reproducible snapshots into dist/
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    _write_json(DIST_BEFORE_OPENAPI, before_doc)
    _write_json(DIST_AFTER_OPENAPI, after_doc)

    before_openapi_sha = _sha256_file(DIST_BEFORE_OPENAPI)
    after_openapi_sha = _sha256_file(DIST_AFTER_OPENAPI)

    # Success status prefixes (configurable via env)
    prefixes_raw = (os.environ.get("OPENAPI_SUCCESS_PREFIXES") or "2").strip()
    success_prefixes = tuple([p.strip() for p in prefixes_raw.split(",") if p.strip()])

    before_norm = normalize_openapi(before_doc)
    after_norm = normalize_openapi(after_doc)

    try:
        raw_report = diff_openapi_core(before_norm, after_norm, success_status_prefixes=success_prefixes)
        gated_report = apply_allowlist_policy(raw_report, policy=policy)
    except Exception as e:
        issues.append(_issue("diff_failed", "openapi_diff", "successful diff", str(e)))
        return _emit_and_exit(issues, json_mode)

    # Classifier fingerprint
    classifier_fingerprint: Dict[str, Dict[str, str]] = {}
    missing: List[str] = []
    for p in CLASSIFIER_FILES:
        if not p.exists():
            missing.append(str(p.relative_to(ROOT)))
            continue
        h = _sha256_file(p)
        classifier_fingerprint[str(p.relative_to(ROOT))] = {
            "sha256": h,
            "sha256_short": h[:12],
        }
    if missing:
        for m in missing:
            issues.append(_issue("missing_file", m, "present", "missing"))
        return _emit_and_exit(issues, json_mode)

    out = gated_report.to_dict()
    out["baseline_tag"] = prev
    out["current_tag"] = current_tag
    out["policy_path"] = str(POLICY_PATH.relative_to(ROOT))
    out["policy_sha256"] = policy_sha
    out["policy_sha256_short"] = policy_sha[:12]

    out["before_openapi_path"] = str(DIST_BEFORE_OPENAPI.relative_to(ROOT))
    out["before_openapi_sha256"] = before_openapi_sha
    out["before_openapi_sha256_short"] = before_openapi_sha[:12]

    out["after_openapi_path"] = str(DIST_AFTER_OPENAPI.relative_to(ROOT))
    out["after_openapi_sha256"] = after_openapi_sha
    out["after_openapi_sha256_short"] = after_openapi_sha[:12]

    out["classifier_fingerprint"] = {
        "files": classifier_fingerprint,
        "file_count": len(classifier_fingerprint),
    }

    try:
        OUT_REPORT.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as e:
        issues.append(_issue("report_emit_failed", str(OUT_REPORT), "written", str(e)))
        return _emit_and_exit(issues, json_mode)

    cf = out.get("classifier_fingerprint", {}).get("files", {})
    cf_short = ", ".join([f"{k}:{v.get('sha256_short')}" for k, v in sorted(cf.items())])
    print(
        f"[openapi-release-gate] baseline={prev} ({before_openapi_sha[:12]}) "
        f"current={current_tag} ({after_openapi_sha[:12]}) {_summarize_report(out)}"
    )
    print(f"[openapi-release-gate] classifier_fingerprint: {cf_short}")

    # Hard requirement: unknowns must be empty after allowlist policy.
    unknown_count = int((out.get("summary") or {}).get("unknown_count") or 0)
    if unknown_count > 0:
        unknowns = out.get("unknown_changes") or []
        issues.append(_issue(
            "unknowns_block_release",
            "openapi_diff_report.json:unknown_changes",
            0,
            unknown_count,
            {"sample": [{"kind": ch.get("kind"), "op": ch.get("op"), "location": ch.get("location")} for ch in unknowns[:10]]},
        ))

    # SemVer major gating: breaking changes require major bump.
    breaking_count = int((out.get("summary") or {}).get("breaking_count") or 0)
    if breaking_count > 0 and cur_major <= prev_major:
        issues.append(_issue(
            "major_bump_required",
            "tag",
            f"major > {prev_major}",
            cur_major,
            {"baseline_tag": prev, "current_tag": current_tag, "breaking_count": breaking_count},
        ))

    if issues:
        return _emit_and_exit(issues, json_mode)

    print("[openapi-release-gate] OK: no unknowns remain after policy.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[openapi-release-gate] ERROR: {e}", file=sys.stderr)
        raise
