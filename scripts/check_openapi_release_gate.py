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


ROOT = Path(__file__).resolve().parents[1]
CURRENT_OPENAPI = ROOT / "docs" / "openapi.json"
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"
OUT_DIR = ROOT / "dist"
OUT_REPORT = OUT_DIR / "openapi_diff_report.json"
OPENAPI_REPO_PATH = "docs/openapi.json"

DIST_BEFORE_OPENAPI = OUT_DIR / "openapi_before.json"
DIST_AFTER_OPENAPI = OUT_DIR / "openapi_after.json"

CLASSIFIER_FILES = [
    ROOT / "src" / "code_audit" / "web_api" / "openapi_normalize.py",
    ROOT / "src" / "code_audit" / "web_api" / "openapi_diff.py",
    ROOT / "src" / "code_audit" / "web_api" / "schema_semver.py",
]


TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


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
    current_tag = _current_tag_from_env()
    cur_major, cur_minor, cur_patch = _parse_tag(current_tag)

    if not CURRENT_OPENAPI.exists():
        raise RuntimeError("Missing docs/openapi.json (current OpenAPI snapshot).")

    if not POLICY_PATH.exists():
        raise RuntimeError("Missing tests/contracts/openapi_breaking_policy.json (required for release gate).")

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

    before_doc = _load_openapi_at_tag(prev)
    after_doc = _load_json(CURRENT_OPENAPI)
    policy = _load_json(POLICY_PATH)
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
    raw_report = diff_openapi_core(before_norm, after_norm, success_status_prefixes=success_prefixes)
    gated_report = apply_allowlist_policy(raw_report, policy=policy)

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
        raise RuntimeError(
            "Missing classifier fingerprint files (release must be self-describing): "
            + ", ".join(missing)
        )

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

    OUT_REPORT.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")

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
        print("")
        print("[openapi-release-gate] FAIL: unknown OpenAPI changes remain after policy application.")
        print("These must be allowlisted (with reason + location for schema kinds) before a release tag can pass.")
        print("")
        unknowns = out.get("unknown_changes") or []
        for i, ch in enumerate(unknowns[:10]):
            kind = ch.get("kind")
            op = ch.get("op")
            loc = ch.get("location")
            print(f"  - {kind} :: {op} @ {loc}")
        if len(unknowns) > 10:
            print(f"  ... ({len(unknowns) - 10} more)")
        return 1

    # SemVer major gating: breaking changes require major bump.
    breaking_count = int((out.get("summary") or {}).get("breaking_count") or 0)
    if breaking_count > 0 and cur_major <= prev_major:
        print("")
        print("[openapi-release-gate] FAIL: breaking OpenAPI changes detected but tag is not a major bump.")
        print(f"Baseline tag: {prev} (major={prev_major})")
        print(f"Current tag:  {current_tag} (major={cur_major})")
        print("")
        print("Rule: if breaking_count > 0 after policy, current_major must be > previous_major.")
        print("Fix: bump major version (v(N+1).0.0) or allowlist/avoid the breaking changes.")
        print("")
        breaks = out.get("breaking_changes") or []
        for i, ch in enumerate(breaks[:10]):
            kind = ch.get("kind")
            op = ch.get("op")
            loc = ch.get("location")
            print(f"  - {kind} :: {op} @ {loc}")
        if len(breaks) > 10:
            print(f"  ... ({len(breaks) - 10} more)")
        return 1

    print("[openapi-release-gate] OK: no unknowns remain after policy.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[openapi-release-gate] ERROR: {e}", file=sys.stderr)
        raise
