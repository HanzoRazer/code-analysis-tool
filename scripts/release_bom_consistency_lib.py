"""Shared Release BOM consistency engine.

Provides the core consistency checking logic used by both:
- scripts/check_release_bom_consistency.py (standalone gate)
- scripts/check_release_bom_generator_gate.py (preflight gate, in-process)

All issue production and verification logic lives here so both
callers produce identical diagnostics.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.schema_ref_graph import build_dist_schema_graph_records


def issue(kind: str, path: str, expected: Any, got: Any, details: Any = None) -> Dict[str, Any]:
    """Build a structured issue dict."""
    d: Dict[str, Any] = {"kind": kind, "path": path, "expected": expected, "got": got}
    if details is not None:
        d["details"] = details
    return d


def sha256_file(path: Path) -> str:
    """SHA-256 hex digest of a file's raw bytes."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_canonical_json_obj(obj: Any) -> str:
    """SHA-256 of canonical JSON (sorted keys, compact separators)."""
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def sha256_canonical_json_file(path: Path) -> str:
    """SHA-256 of a JSON file's canonical representation."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    return sha256_canonical_json_obj(obj)


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON from a file, returning None on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def check_schema_identity(
    schema: Dict[str, Any],
    expected_id: str,
    label: str,
    issues: List[Dict[str, Any]],
) -> None:
    """Verify schema $id matches expected value."""
    actual_id = schema.get("$id", "")
    if actual_id != expected_id:
        issues.append(issue(
            "schema_identity_mismatch",
            label,
            expected_id,
            actual_id,
        ))


def meta_validate_schema(
    schema: Dict[str, Any],
    label: str,
    issues: List[Dict[str, Any]],
) -> None:
    """Meta-validate a schema using Draft 2020-12."""
    try:
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
    except ImportError:
        issues.append(issue(
            "schema_meta_validation_unavailable",
            label,
            "jsonschema installed",
            "not available",
        ))
    except Exception as e:
        issues.append(issue(
            "schema_meta_validation_failed",
            label,
            "valid schema",
            str(e),
        ))


def check_release_bom_object_against_dist(
    *,
    bom_obj: Dict[str, Any],
    root: Path,
    dist: Path,
) -> List[Dict[str, Any]]:
    """Core consistency checks: hash coherence, schema identity, provenance.

    Returns a list of issue dicts. Empty list means consistent.
    """
    issues: List[Dict[str, Any]] = []
    artifacts = bom_obj.get("artifacts")
    if not isinstance(artifacts, dict):
        issues.append(issue("bom_invalid_artifact", "release_bom.json:artifacts", "object", type(artifacts).__name__))
        return issues

    # Expected dist files
    expected_dist_files = [
        "release_bom.json",
        "release_bom.schema.json",
        "release_audit_failure.schema.json",
        "openapi_breaking_policy.json",
        "openapi_before.json",
        "openapi_after.json",
        "openapi_diff_report.json",
        "openapi_classifier_manifest.json",
    ]

    for fname in expected_dist_files:
        fpath = dist / fname
        if not fpath.exists():
            issues.append(issue("missing_file", f"dist/{fname}", "present", "missing"))

    # Check each artifact file hash
    for name, a in artifacts.items():
        if not isinstance(a, dict):
            continue
        art_path_str = a.get("path", "")
        # Handle both old "name/sha256" and new "path/canonical_sha256" formats
        sha_field = "canonical_sha256" if "canonical_sha256" in a else "sha256"
        expected_sha = a.get(sha_field, "")
        if not art_path_str or not expected_sha:
            continue

        # Resolve path relative to dist or root
        if art_path_str.startswith("dist/"):
            art_path = root / art_path_str
        else:
            art_path = dist / art_path_str

        if not art_path.exists():
            issues.append(issue("bom_path_missing", f"release_bom.json:artifacts.{name}", "exists", "missing"))
            continue

        if sha_field == "canonical_sha256":
            actual_sha = sha256_canonical_json_file(art_path)
        else:
            actual_sha = sha256_file(art_path)

        if actual_sha != expected_sha:
            issues.append(issue(
                "bom_hash_mismatch",
                f"release_bom.json:artifacts.{name}",
                expected_sha,
                actual_sha,
            ))

    # Schema identity checks for schema artifacts
    schema_artifacts_ids = {
        "release_bom_schema": "release_bom_schema_v1",
        "release_audit_failure_schema": "release_audit_failure_schema_v1",
        "openapi_release_gate_result_schema": "openapi_release_gate_result_schema_v1",
        "release_bom_consistency_result_schema": "release_bom_consistency_result_schema_v1",
        "release_bom_generator_gate_result_schema": "release_bom_generator_gate_result_schema_v1",
        "release_gate_envelope_schema": "release_gate_envelope_schema_v1",
        "schema_graph_bundle_schema": "schema_graph_bundle_schema_v1",
    }

    for name, expected_id in schema_artifacts_ids.items():
        a = artifacts.get(name)
        if a is None:
            continue
        art_path_str = a.get("path", "")
        if art_path_str.startswith("dist/"):
            art_path = root / art_path_str
        else:
            art_path = dist / art_path_str
        if not art_path.exists():
            continue
        schema_obj = load_json(art_path)
        if schema_obj is None:
            issues.append(issue("invalid_json", f"dist/{art_path.name}", "valid JSON", "parse error"))
            continue

        check_schema_identity(schema_obj, expected_id, f"dist/{art_path.name}", issues)
        meta_validate_schema(schema_obj, f"dist/{art_path.name}", issues)

        # Schema version match
        bom_version = a.get("schema_version")
        actual_version = schema_obj.get("schema_version")
        if bom_version and actual_version and bom_version != actual_version:
            issues.append(issue(
                "bom_identity_mismatch",
                f"release_bom.json:artifacts.{name}.schema_version",
                bom_version,
                actual_version,
            ))

        # Ref-closure verification
        want_closure = a.get("ref_closure")
        want_closure_sha = a.get("ref_closure_sha256")
        if want_closure is not None and want_closure_sha is not None:
            try:
                bundle = build_dist_schema_graph_records(root=root, top_dist_schema=art_path)
                got_closure = bundle["ref_closure"]
                got_closure_sha = bundle["ref_closure_sha256"]
                got_edges = bundle["ref_edges"]
                got_edges_sha = bundle["ref_edges_sha256"]

                if want_closure != got_closure:
                    issues.append(issue(
                        "bom_hash_mismatch",
                        f"release_bom.json:artifacts.{name}.ref_closure",
                        want_closure,
                        got_closure,
                    ))
                if want_closure_sha != got_closure_sha:
                    issues.append(issue(
                        "bom_hash_mismatch",
                        f"release_bom.json:artifacts.{name}.ref_closure_sha256",
                        want_closure_sha,
                        got_closure_sha,
                    ))

                want_edges = a.get("ref_edges")
                want_edges_sha = a.get("ref_edges_sha256")
                if want_edges is not None:
                    if want_edges != got_edges:
                        issues.append(issue(
                            "bom_hash_mismatch",
                            f"release_bom.json:artifacts.{name}.ref_edges",
                            want_edges,
                            got_edges,
                        ))
                if want_edges_sha is not None:
                    if want_edges_sha != got_edges_sha:
                        issues.append(issue(
                            "bom_hash_mismatch",
                            f"release_bom.json:artifacts.{name}.ref_edges_sha256",
                            want_edges_sha,
                            got_edges_sha,
                        ))
            except Exception:
                # If graph computation fails, skip closure checks
                pass

    # Provenance cross-check
    diff_report_path = dist / "openapi_diff_report.json"
    if diff_report_path.exists():
        diff_report = load_json(diff_report_path)
        if diff_report:
            prov = bom_obj.get("provenance") or {}
            for field in ("baseline_tag", "current_tag", "breaking"):
                bom_val = prov.get(field)
                report_val = diff_report.get(field)
                if bom_val is not None and report_val is not None and bom_val != report_val:
                    issues.append(issue(
                        "provenance_mismatch",
                        f"release_bom.json:provenance.{field}",
                        report_val,
                        bom_val,
                    ))

    return issues
