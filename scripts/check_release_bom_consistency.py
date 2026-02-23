"""Validate release BOM consistency.

Checks all dist/ artifacts for hash coherence, schema identity matches,
and provenance cross-references with the diff report.

Usage:
    python scripts/check_release_bom_consistency.py [--json]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

BOM_PATH = DIST / "release_bom.json"
BOM_SCHEMA_PATH = DIST / "release_bom.schema.json"
AUDIT_SCHEMA_PATH = DIST / "release_audit_failure.schema.json"
DIFF_REPORT_PATH = DIST / "openapi_diff_report.json"
CONSISTENCY_RESULT_SCHEMA = ROOT / "schemas" / "release_bom_consistency_result.schema.json"

_EXPECTED_DIST_FILES = [
    "release_bom.json",
    "release_bom.schema.json",
    "release_audit_failure.schema.json",
    "openapi_breaking_policy.json",
    "openapi_before.json",
    "openapi_after.json",
    "openapi_diff_report.json",
    "openapi_classifier_manifest.json",
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_ci_true() -> bool:
    return os.environ.get("CI", "").lower() in ("true", "1", "yes")


class _ConsistencyChecker:
    def __init__(self) -> None:
        self.issues: List[Dict[str, Any]] = []
        self.ok = True

    def _issue(self, kind: str, message: str, **extra: Any) -> None:
        entry: Dict[str, Any] = {"kind": kind, "message": message}
        entry.update(extra)
        self.issues.append(entry)
        self.ok = False

    def _req_file(self, path: Path, label: str) -> bool:
        if not path.exists():
            self._issue("missing_file", f"Missing: {label} → {path}", path=str(path))
            return False
        return True

    def _load_json_or_issue(self, path: Path, label: str) -> Optional[Dict[str, Any]]:
        if not self._req_file(path, label):
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError) as e:
            self._issue("invalid_json", f"Invalid JSON in {label}: {e}", path=str(path))
            return None

    def _check_bom_artifact_file_sha(self, bom: Dict[str, Any], name: str) -> None:
        artifacts = bom.get("artifacts") or {}
        entry = artifacts.get(name)
        if entry is None:
            self._issue("bom_missing_artifact", f"BOM missing artifact: {name}", artifact=name)
            return
        art_path = DIST / entry.get("path", "")
        expected_sha = entry.get("sha256", "")
        if not art_path.exists():
            self._issue("bom_path_missing", f"Artifact path missing: {art_path}", artifact=name, path=str(art_path))
            return
        actual_sha = _sha256_file(art_path)
        if actual_sha != expected_sha:
            self._issue(
                "bom_hash_mismatch",
                f"Hash mismatch for {name}: expected {expected_sha[:12]} got {actual_sha[:12]}",
                artifact=name,
                expected=expected_sha,
                actual=actual_sha,
            )

    def _check_schema_identity(
        self, schema: Dict[str, Any], expected_id: str, label: str
    ) -> None:
        actual_id = schema.get("$id", "")
        if actual_id != expected_id:
            self._issue(
                "schema_identity_mismatch",
                f"Schema identity mismatch for {label}: expected '{expected_id}' got '{actual_id}'",
                expected=expected_id,
                actual=actual_id,
            )

    def _meta_validate_schema(self, schema: Dict[str, Any], label: str) -> None:
        try:
            import jsonschema  # type: ignore

            jsonschema.Draft202012Validator.check_schema(schema)
        except ImportError:
            self._issue(
                "schema_meta_validation_unavailable",
                f"jsonschema not available; cannot meta-validate {label}",
            )
        except jsonschema.SchemaError as e:
            self._issue(
                "schema_meta_validation_failed",
                f"Schema meta-validation failed for {label}: {e.message}",
            )

    def _check_provenance(self, bom: Dict[str, Any], diff_report: Dict[str, Any]) -> None:
        prov = bom.get("provenance") or {}
        bom_policy_sha = prov.get("policy_sha256", "")
        report_policy_sha = diff_report.get("policy_sha256", "")
        if bom_policy_sha and report_policy_sha and bom_policy_sha != report_policy_sha:
            self._issue(
                "provenance_mismatch",
                f"BOM provenance policy_sha256 does not match diff report: "
                f"{bom_policy_sha[:12]} vs {report_policy_sha[:12]}",
                field="policy_sha256",
                bom_value=bom_policy_sha,
                report_value=report_policy_sha,
            )

        for field in ("baseline_tag", "current_tag", "breaking"):
            bom_val = prov.get(field)
            report_val = diff_report.get(field)
            if bom_val is not None and report_val is not None and bom_val != report_val:
                self._issue(
                    "provenance_mismatch",
                    f"BOM provenance {field} does not match diff report: {bom_val} vs {report_val}",
                    field=field,
                    bom_value=bom_val,
                    report_value=report_val,
                )

        summary = diff_report.get("summary") or {}
        for count_field in ("breaking_count", "non_breaking_count", "unknown_count"):
            bom_val = prov.get(count_field)
            report_val = summary.get(count_field)
            if bom_val is not None and report_val is not None and bom_val != report_val:
                self._issue(
                    "provenance_mismatch",
                    f"BOM provenance {count_field} does not match diff report summary: {bom_val} vs {report_val}",
                    field=count_field,
                    bom_value=bom_val,
                    report_value=report_val,
                )

    def run(self) -> Dict[str, Any]:
        # Load BOM
        bom = self._load_json_or_issue(BOM_PATH, "release_bom.json")
        if bom is None:
            return self._result()

        # Check all expected dist files exist
        for fname in _EXPECTED_DIST_FILES:
            fpath = DIST / fname
            if not fpath.exists():
                self._issue("bom_path_missing", f"Expected dist file missing: {fname}", path=str(fpath))

        # Check each artifact hash
        artifact_names = [
            "release_bom_schema",
            "release_audit_failure_schema",
            "openapi_breaking_policy",
            "openapi_before_snapshot",
            "openapi_after_snapshot",
            "openapi_diff_report",
            "openapi_classifier_manifest",
        ]
        for name in artifact_names:
            self._check_bom_artifact_file_sha(bom, name)

        # Schema identity checks
        bom_schema = self._load_json_or_issue(BOM_SCHEMA_PATH, "release_bom.schema.json")
        if bom_schema:
            self._check_schema_identity(
                bom_schema,
                "https://code-audit.dev/schemas/release_bom.schema.json",
                "release_bom.schema.json",
            )
            self._meta_validate_schema(bom_schema, "release_bom.schema.json")

        audit_schema = self._load_json_or_issue(AUDIT_SCHEMA_PATH, "release_audit_failure.schema.json")
        if audit_schema:
            self._check_schema_identity(
                audit_schema,
                "https://code-audit.dev/schemas/release_audit_failure.schema.json",
                "release_audit_failure.schema.json",
            )
            self._meta_validate_schema(audit_schema, "release_audit_failure.schema.json")

        # Provenance cross-check
        diff_report = self._load_json_or_issue(DIFF_REPORT_PATH, "openapi_diff_report.json")
        if diff_report:
            self._check_provenance(bom, diff_report)

        return self._result()

    def _result(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "ok": self.ok,
            "issue_count": len(self.issues),
            "issues": self.issues,
        }


def _emit_failure_json(result: Dict[str, Any]) -> None:
    print(json.dumps(result, indent=2, sort_keys=True))


def _emit_failure_human(result: Dict[str, Any]) -> None:
    issues = result.get("issues") or []
    print(f"[bom-consistency] FAIL: {len(issues)} issue(s) found.")
    for i, issue in enumerate(issues):
        kind = issue.get("kind", "?")
        msg = issue.get("message", "")
        print(f"  [{i + 1}] {kind}: {msg}")


def main() -> int:
    json_mode = "--json" in sys.argv

    checker = _ConsistencyChecker()
    result = checker.run()

    if result["ok"]:
        if json_mode:
            _emit_failure_json(result)
        else:
            print("[bom-consistency] OK: all checks passed.")
        return 0
    else:
        if json_mode:
            _emit_failure_json(result)
        else:
            _emit_failure_human(result)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
