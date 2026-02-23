"""Generate a release BOM (Bill of Materials) JSON file.

Copies all release artifacts into dist/ and produces dist/release_bom.json
describing the complete self-contained release payload.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Source locations
SCHEMA_BOM = ROOT / "schemas" / "release_bom.schema.json"
SCHEMA_AUDIT = ROOT / "schemas" / "release_audit_failure.schema.json"
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"
CLASSIFIER_MANIFEST = ROOT / "tests" / "contracts" / "openapi_classifier_manifest.json"
DIFF_REPORT_PATH = DIST / "openapi_diff_report.json"

# Dist destinations
DIST_BOM_SCHEMA = DIST / "release_bom.schema.json"
DIST_AUDIT_SCHEMA = DIST / "release_audit_failure.schema.json"
DIST_POLICY = DIST / "openapi_breaking_policy.json"
DIST_CLASSIFIER_MANIFEST = DIST / "openapi_classifier_manifest.json"
DIST_BEFORE_OPENAPI = DIST / "openapi_before.json"
DIST_AFTER_OPENAPI = DIST / "openapi_after.json"
DIST_BOM = DIST / "release_bom.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"


def _sha256_canonical_json_file(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    return hashlib.sha256(_canonical_json_bytes(data)).hexdigest()


def _copy_into_dist(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(dst))


def _require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeError(f"Missing required file for BOM: {label} → {path}")


def _select_classifier_fingerprint(diff_report: Dict[str, Any]) -> Dict[str, Any]:
    fp = diff_report.get("classifier_fingerprint")
    if not fp:
        raise RuntimeError("Diff report missing classifier_fingerprint section.")
    return fp


def _make_artifact_entry(name: str, dist_path: Path, sha: str) -> Dict[str, Any]:
    return {
        "name": name,
        "path": str(dist_path.relative_to(DIST)),
        "sha256": sha,
        "sha256_short": sha[:12],
    }


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)

    # Copy artifacts into dist/
    _require_file(SCHEMA_BOM, "release_bom.schema.json")
    _copy_into_dist(SCHEMA_BOM, DIST_BOM_SCHEMA)

    _require_file(SCHEMA_AUDIT, "release_audit_failure.schema.json")
    _copy_into_dist(SCHEMA_AUDIT, DIST_AUDIT_SCHEMA)

    _require_file(POLICY_PATH, "openapi_breaking_policy.json")
    _copy_into_dist(POLICY_PATH, DIST_POLICY)

    _require_file(CLASSIFIER_MANIFEST, "openapi_classifier_manifest.json")
    _copy_into_dist(CLASSIFIER_MANIFEST, DIST_CLASSIFIER_MANIFEST)

    # Snapshots and diff report should already be in dist/
    _require_file(DIST_BEFORE_OPENAPI, "dist/openapi_before.json")
    _require_file(DIST_AFTER_OPENAPI, "dist/openapi_after.json")
    _require_file(DIFF_REPORT_PATH, "dist/openapi_diff_report.json")

    diff_report = json.loads(DIFF_REPORT_PATH.read_text(encoding="utf-8"))
    classifier_fp = _select_classifier_fingerprint(diff_report)

    # Provenance from diff report
    provenance: Dict[str, Any] = {
        "baseline_tag": diff_report.get("baseline_tag", ""),
        "current_tag": diff_report.get("current_tag", ""),
        "breaking": diff_report.get("breaking", False),
        "breaking_count": (diff_report.get("summary") or {}).get("breaking_count", 0),
        "non_breaking_count": (diff_report.get("summary") or {}).get("non_breaking_count", 0),
        "unknown_count": (diff_report.get("summary") or {}).get("unknown_count", 0),
        "policy_sha256": diff_report.get("policy_sha256", ""),
        "classifier_fingerprint": classifier_fp,
    }

    # Build artifacts list
    artifacts: list[Dict[str, Any]] = [
        _make_artifact_entry("release_bom_schema", DIST_BOM_SCHEMA, _sha256_file(DIST_BOM_SCHEMA)),
        _make_artifact_entry("release_audit_failure_schema", DIST_AUDIT_SCHEMA, _sha256_file(DIST_AUDIT_SCHEMA)),
        _make_artifact_entry("openapi_breaking_policy", DIST_POLICY, _sha256_file(DIST_POLICY)),
        _make_artifact_entry("openapi_before_snapshot", DIST_BEFORE_OPENAPI, _sha256_file(DIST_BEFORE_OPENAPI)),
        _make_artifact_entry("openapi_after_snapshot", DIST_AFTER_OPENAPI, _sha256_file(DIST_AFTER_OPENAPI)),
        _make_artifact_entry("openapi_diff_report", DIFF_REPORT_PATH, _sha256_file(DIFF_REPORT_PATH)),
        _make_artifact_entry("openapi_classifier_manifest", DIST_CLASSIFIER_MANIFEST, _sha256_file(DIST_CLASSIFIER_MANIFEST)),
    ]

    bom: Dict[str, Any] = {
        "version": 1,
        "provenance": provenance,
        "artifacts": {a["name"]: a for a in artifacts},
    }

    DIST_BOM.write_text(
        json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"[generate-release-bom] Wrote {DIST_BOM}")
    for a in artifacts:
        print(f"  {a['name']}: {a['sha256_short']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[generate-release-bom] ERROR: {e}", file=sys.stderr)
        raise
