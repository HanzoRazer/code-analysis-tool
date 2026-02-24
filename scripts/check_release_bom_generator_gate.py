"""Release BOM generator preflight gate.

Runs the BOM generator in --check mode, validates the temp BOM,
and performs self-consistency checks including ref-edge hash verification
and full BOM consistency.

Usage:
    python scripts/check_release_bom_generator_gate.py [--json]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.release_bom_consistency_runner import run_release_bom_consistency_check
from scripts.release_gate_json import (
    build_gate_failure_json,
    emit_gate_failure_human,
    emit_gate_failure_json,
    is_ci_true,
)
from scripts.schema_ref_kind import (
    edge_identity_key,
    edge_sort_key,
    ref_edges_sha256,
    trace_sha256_short,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
TMP_BOM = DIST / "release_bom.json"
BOM_SCHEMA = DIST / "release_bom.schema.json"

OUT_GATE_RESULT = DIST / "release_bom_generator_gate_result.json"


def _issue(kind: str, path: str, expected: Any, got: Any, details: Any = None) -> Dict[str, Any]:
    d: Dict[str, Any] = {"kind": kind, "path": path, "expected": expected, "got": got}
    if details is not None:
        d["details"] = details
    return d


def _load_json_or_issue(
    path: Path, label: str, issues: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    if not path.exists():
        issues.append(_issue("missing_input", str(path), "present", "missing"))
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        issues.append(_issue("invalid_input_json", str(path), "valid JSON", str(e)))
        return None


def _validate_bom_against_dist_schema(
    bom_obj: Dict[str, Any],
    issues: List[Dict[str, Any]],
) -> None:
    """Validate temp BOM against shipped BOM schema."""
    if not BOM_SCHEMA.exists():
        issues.append(_issue("missing_dist_output", str(BOM_SCHEMA), "present", "missing"))
        return
    try:
        import jsonschema
    except ImportError:
        issues.append(_issue(
            "schema_meta_validation_unavailable",
            str(BOM_SCHEMA),
            "jsonschema installed",
            "not available",
        ))
        return
    schema = json.loads(BOM_SCHEMA.read_text(encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    errors = list(v.iter_errors(bom_obj))
    if errors:
        for err in errors[:10]:
            path = ".".join(str(p) for p in err.absolute_path) or "(root)"
            issues.append(_issue(
                "schema_meta_validation_failed",
                f"release_bom.json:{path}",
                "valid",
                err.message,
            ))


def _preflight_verify_ref_edges_hashes(
    bom_obj: Dict[str, Any],
    issues: List[Dict[str, Any]],
) -> None:
    """Generator preflight self-consistency check for ref-edge hashes."""
    artifacts = bom_obj.get("artifacts")
    if not isinstance(artifacts, dict):
        issues.append(_issue(
            "bom_invalid_artifacts",
            "release_bom.json:artifacts",
            "object",
            type(artifacts).__name__,
        ))
        return

    for name, a in artifacts.items():
        if not isinstance(a, dict):
            continue
        ref_edges = a.get("ref_edges")
        ref_edges_sha = a.get("ref_edges_sha256")

        # Only enforce for artifacts that declare edges.
        if ref_edges is None and ref_edges_sha is None:
            continue

        if not isinstance(ref_edges, list):
            issues.append(_issue(
                "bom_invalid_ref_edges",
                f"release_bom.json:artifacts.{name}.ref_edges",
                "array",
                type(ref_edges).__name__,
            ))
            continue
        if not isinstance(ref_edges_sha, str):
            issues.append(_issue(
                "bom_invalid_ref_edges_sha",
                f"release_bom.json:artifacts.{name}.ref_edges_sha256",
                "sha256 hex string",
                ref_edges_sha,
            ))
            continue

        # Validate per-edge short hash correctness
        for i, e in enumerate(ref_edges):
            if not isinstance(e, dict):
                issues.append(_issue(
                    "bom_invalid_ref_edge_item",
                    f"release_bom.json:artifacts.{name}.ref_edges[{i}]",
                    "object",
                    type(e).__name__,
                ))
                continue
            trace = e.get("kind_trace_compact")
            short = e.get("kind_trace_sha256_short")
            if isinstance(trace, list) and isinstance(short, str):
                got_short = trace_sha256_short(trace)
                if got_short != short:
                    issues.append(_issue(
                        "bom_ref_edge_trace_short_mismatch",
                        f"release_bom.json:artifacts.{name}.ref_edges[{i}].kind_trace_sha256_short",
                        short,
                        got_short,
                        {"from": e.get("from"), "to": e.get("to")},
                    ))

        # Recompute ref_edges_sha256 over normalized edge list
        got = ref_edges_sha256(ref_edges)
        if got != ref_edges_sha:
            issues.append(_issue(
                "bom_ref_edges_sha_mismatch",
                f"release_bom.json:artifacts.{name}.ref_edges_sha256",
                ref_edges_sha,
                got,
                {"artifact": name, "edge_count": len(ref_edges)},
            ))


def _preflight_verify_ref_edges_sorted_unique(
    bom_obj: Dict[str, Any],
    issues: List[Dict[str, Any]],
) -> None:
    """Enforce edge list sorting + uniqueness beyond JSON Schema."""
    artifacts = bom_obj.get("artifacts")
    if not isinstance(artifacts, dict):
        return

    for name, a in artifacts.items():
        if not isinstance(a, dict):
            continue
        ref_edges = a.get("ref_edges")
        if ref_edges is None or not isinstance(ref_edges, list):
            continue

        # Check duplicates
        seen: Dict[Any, int] = {}
        for i, e in enumerate(ref_edges):
            if not isinstance(e, dict):
                continue
            ident = edge_identity_key(e)
            if ident in seen:
                issues.append(_issue(
                    "bom_ref_edges_duplicate",
                    f"release_bom.json:artifacts.{name}.ref_edges",
                    "unique edges",
                    {"first_index": seen[ident], "dup_index": i},
                    {"artifact": name},
                ))
            else:
                seen[ident] = i

        # Enforce canonical sorting
        dict_edges = [e for e in ref_edges if isinstance(e, dict)]
        sorted_edges = sorted(dict_edges, key=edge_sort_key)
        for i, (got, want) in enumerate(zip(dict_edges, sorted_edges)):
            if edge_sort_key(got) != edge_sort_key(want):
                issues.append(_issue(
                    "bom_ref_edges_not_sorted",
                    f"release_bom.json:artifacts.{name}.ref_edges",
                    "sorted by canonical key",
                    {"first_out_of_order_index": i},
                    {"artifact": name},
                ))
                break


def main() -> int:
    json_mode = "--json" in sys.argv
    issues: List[Dict[str, Any]] = []

    # Load temp BOM
    tmp_obj = _load_json_or_issue(TMP_BOM, "release_bom.json", issues)
    if isinstance(tmp_obj, dict):
        _validate_bom_against_dist_schema(tmp_obj, issues)

        if not issues:
            _preflight_verify_ref_edges_hashes(tmp_obj, issues)

        if not issues:
            _preflight_verify_ref_edges_sorted_unique(tmp_obj, issues)

        if not issues:
            # Single source of truth: run the same consistency runner
            issues.extend(run_release_bom_consistency_check(bom_obj=tmp_obj, root=ROOT))

    if not issues:
        print("[bom-generator-gate] OK: all preflight checks passed.")
        return 0

    result = build_gate_failure_json(
        kind="release_bom_generator_gate_failed",
        path="dist/*",
        expected="consistent BOM",
        got=f"{len(issues)} issue(s)",
        details=issues,
    )

    # Write result to dist
    DIST.mkdir(parents=True, exist_ok=True)
    OUT_GATE_RESULT.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if json_mode:
        emit_gate_failure_json(result)
    else:
        emit_gate_failure_human(result, prefix="bom-generator-gate")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
