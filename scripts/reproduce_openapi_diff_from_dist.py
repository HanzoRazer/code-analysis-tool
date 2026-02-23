"""Reproduce OpenAPI diff from dist/ artifacts.

Re-runs the diff engine against the before/after snapshots in dist/
and verifies the result matches the shipped diff report. Also validates
the BOM schema and artifact hashes.

Usage:
    python scripts/reproduce_openapi_diff_from_dist.py [--print] [--no-write]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from code_audit.web_api.openapi_diff import apply_allowlist_policy, diff_openapi_core
from code_audit.web_api.openapi_normalize import normalize_openapi


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

BOM_PATH = DIST / "release_bom.json"
BOM_SCHEMA_PATH = DIST / "release_bom.schema.json"
BEFORE_PATH = DIST / "openapi_before.json"
AFTER_PATH = DIST / "openapi_after.json"
DIFF_REPORT_PATH = DIST / "openapi_diff_report.json"
POLICY_PATH = DIST / "openapi_breaking_policy.json"
AUDIT_FAILURE_PATH = DIST / "audit_failure.json"
AUDIT_SCHEMA_PATH = DIST / "release_audit_failure.schema.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_ci() -> bool:
    return os.environ.get("CI", "").lower() in ("true", "1", "yes")


def _fail(kind: str, message: str, **detail: Any) -> Dict[str, Any]:
    return {"kind": kind, "message": message, **detail}


def _emit_failure(failures: List[Dict[str, Any]], no_write: bool) -> None:
    audit = {
        "version": 1,
        "ok": False,
        "failure_count": len(failures),
        "failures": failures,
    }
    if not no_write and (_is_ci() or "--write" in sys.argv):
        AUDIT_FAILURE_PATH.write_text(
            json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"[reproduce] Wrote audit failure: {AUDIT_FAILURE_PATH}")

    print(f"[reproduce] FAIL: {len(failures)} failure(s).")
    for i, f in enumerate(failures):
        print(f"  [{i + 1}] {f.get('kind')}: {f.get('message')}")


def _validate_bom_schema(bom: Dict[str, Any]) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    if not BOM_SCHEMA_PATH.exists():
        failures.append(_fail("bom_schema_validation", "BOM schema not found in dist/"))
        return failures

    try:
        import jsonschema  # type: ignore

        schema = json.loads(BOM_SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        errors = list(validator.iter_errors(bom))
        if errors:
            for err in errors[:5]:
                path = ".".join(str(p) for p in err.absolute_path) or "(root)"
                failures.append(_fail(
                    "bom_schema_validation",
                    f"BOM schema validation error at {path}: {err.message}",
                ))
    except ImportError:
        pass  # Skip validation if jsonschema is not available
    return failures


def _assert_bom_hashes(bom: Dict[str, Any]) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    artifacts = bom.get("artifacts") or {}
    for name, entry in artifacts.items():
        art_path = DIST / entry.get("path", "")
        expected = entry.get("sha256", "")
        if not art_path.exists():
            failures.append(_fail(
                "bom_hash_verification",
                f"Artifact file missing: {name} → {art_path}",
                artifact=name,
            ))
            continue
        actual = _sha256_file(art_path)
        if actual != expected:
            failures.append(_fail(
                "bom_hash_verification",
                f"Hash mismatch for {name}: expected {expected[:12]} got {actual[:12]}",
                artifact=name,
                expected=expected,
                actual=actual,
            ))
    return failures


def _recompute_report(
    before: Dict[str, Any],
    after: Dict[str, Any],
    policy: Dict[str, Any],
    success_prefixes: tuple[str, ...] = ("2",),
) -> Dict[str, Any]:
    before_norm = normalize_openapi(before)
    after_norm = normalize_openapi(after)
    raw = diff_openapi_core(before_norm, after_norm, success_status_prefixes=success_prefixes)
    gated = apply_allowlist_policy(raw, policy=policy)
    return gated.to_dict()


def main() -> int:
    print_mode = "--print" in sys.argv
    no_write = "--no-write" in sys.argv

    failures: List[Dict[str, Any]] = []

    # Phase 1: Load and validate BOM
    if not BOM_PATH.exists():
        failures.append(_fail("input_type_error", f"BOM not found: {BOM_PATH}"))
        _emit_failure(failures, no_write)
        return 1

    bom = json.loads(BOM_PATH.read_text(encoding="utf-8"))
    failures.extend(_validate_bom_schema(bom))
    if failures:
        _emit_failure(failures, no_write)
        return 1

    # Phase 2: Verify BOM hashes
    failures.extend(_assert_bom_hashes(bom))
    if failures:
        _emit_failure(failures, no_write)
        return 1

    # Phase 3: Reproduce the diff
    for p, label in [
        (BEFORE_PATH, "openapi_before.json"),
        (AFTER_PATH, "openapi_after.json"),
        (POLICY_PATH, "openapi_breaking_policy.json"),
        (DIFF_REPORT_PATH, "openapi_diff_report.json"),
    ]:
        if not p.exists():
            failures.append(_fail("input_type_error", f"Missing: {label} → {p}"))

    if failures:
        _emit_failure(failures, no_write)
        return 1

    before = json.loads(BEFORE_PATH.read_text(encoding="utf-8"))
    after = json.loads(AFTER_PATH.read_text(encoding="utf-8"))
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    original_report = json.loads(DIFF_REPORT_PATH.read_text(encoding="utf-8"))

    # Get success prefixes from env
    prefixes_raw = (os.environ.get("OPENAPI_SUCCESS_PREFIXES") or "2").strip()
    success_prefixes = tuple(p.strip() for p in prefixes_raw.split(",") if p.strip())

    reproduced = _recompute_report(before, after, policy, success_prefixes)

    # Compare key fields
    for field in ("breaking",):
        if reproduced.get(field) != original_report.get(field):
            failures.append(_fail(
                "diff_report_mismatch",
                f"Reproduced report {field} differs: {reproduced.get(field)} vs {original_report.get(field)}",
                field=field,
                reproduced=reproduced.get(field),
                original=original_report.get(field),
            ))

    for count_field in ("breaking_count", "non_breaking_count", "unknown_count"):
        repr_val = (reproduced.get("summary") or {}).get(count_field)
        orig_val = (original_report.get("summary") or {}).get(count_field)
        if repr_val != orig_val:
            failures.append(_fail(
                "diff_report_mismatch",
                f"Reproduced report summary.{count_field} differs: {repr_val} vs {orig_val}",
                field=f"summary.{count_field}",
                reproduced=repr_val,
                original=orig_val,
            ))

    if failures:
        _emit_failure(failures, no_write)
        return 1

    if print_mode:
        print(json.dumps(reproduced, indent=2, sort_keys=True))

    print("[reproduce] OK: diff reproduction matches shipped report.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[reproduce] ERROR: {e}", file=sys.stderr)
        raise
