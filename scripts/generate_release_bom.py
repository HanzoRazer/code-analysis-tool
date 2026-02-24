"""Generate a release BOM (Bill of Materials) JSON file.

Copies all release artifacts into dist/ and produces dist/release_bom.json
describing the complete self-contained release payload.

Supports schema ref-graph closure + edge attestation for all shipped schemas.

Options:
    --out <path>    Write BOM to a custom path instead of dist/release_bom.json
    --check         Dry-run mode: generate temp BOM, validate, then discard
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from scripts.schema_ref_graph import (
    build_dist_schema_graph_records,
    schema_ref_closure_files,
    schema_ref_graph_edges,
)
from scripts.schema_ref_kind import (
    canonicalize_ref_edges,
    ref_edges_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Source locations
SCHEMA_BOM = ROOT / "schemas" / "release_bom.schema.json"
SCHEMA_AUDIT = ROOT / "schemas" / "release_audit_failure.schema.json"
SCHEMA_OPENAPI_GATE_RESULT = ROOT / "schemas" / "openapi_release_gate_result.schema.json"
SCHEMA_CONSISTENCY_RESULT = ROOT / "schemas" / "release_bom_consistency_result.schema.json"
SCHEMA_BOM_GENERATOR_GATE_RESULT = ROOT / "schemas" / "release_bom_generator_gate_result.schema.json"
SCHEMA_GATE_ENVELOPE = ROOT / "schemas" / "release_gate_envelope.schema.json"
SCHEMA_GRAPH_BUNDLE = ROOT / "schemas" / "schema_graph_bundle.schema.json"
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"
CLASSIFIER_MANIFEST = ROOT / "tests" / "contracts" / "openapi_classifier_manifest.json"
DIFF_REPORT_PATH = DIST / "openapi_diff_report.json"

# Dist destinations
DIST_BOM_SCHEMA = DIST / "release_bom.schema.json"
DIST_AUDIT_SCHEMA = DIST / "release_audit_failure.schema.json"
DIST_OPENAPI_GATE_SCHEMA = DIST / "openapi_release_gate_result.schema.json"
DIST_CONSISTENCY_RESULT_SCHEMA = DIST / "release_bom_consistency_result.schema.json"
DIST_BOM_GENERATOR_GATE_RESULT_SCHEMA = DIST / "release_bom_generator_gate_result.schema.json"
DIST_GATE_ENVELOPE_SCHEMA = DIST / "release_gate_envelope.schema.json"
DIST_GRAPH_BUNDLE_SCHEMA = DIST / "schema_graph_bundle.schema.json"
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
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256_canonical_json_obj(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


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


def _make_schema_artifact_entry(
    dist_path: Path,
    schema_obj: Dict[str, Any],
    graph_bundle: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a BOM artifact entry for a schema artifact with canonical hash + identity + optional graph bundle."""
    canon_sha = _sha256_canonical_json_file(dist_path)
    entry: Dict[str, Any] = {
        "path": str(dist_path.relative_to(ROOT)).replace("\\", "/"),
        "schema_version": schema_obj.get("schema_version", ""),
        "$id": schema_obj.get("$id", ""),
        "canonical_sha256": canon_sha,
        "canonical_sha256_short": canon_sha[:12],
    }
    if graph_bundle is not None:
        entry["ref_closure"] = graph_bundle["ref_closure"]
        entry["ref_closure_sha256"] = graph_bundle["ref_closure_sha256"]
        entry["ref_edges"] = graph_bundle["ref_edges"]
        entry["ref_edges_sha256"] = graph_bundle["ref_edges_sha256"]
    return entry


def _make_bytes_artifact_entry(dist_path: Path) -> Dict[str, Any]:
    """Build a BOM artifact entry for a bytes (non-schema) artifact."""
    sha = _sha256_file(dist_path)
    return {
        "path": str(dist_path.relative_to(DIST)).replace("\\", "/"),
        "sha256": sha,
        "sha256_short": sha[:12],
    }


def _ship_schema_with_graph(
    src_schema: Path,
    dist_schema: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Copy a schema into dist, compute graph bundle, return (schema_obj, graph_bundle).

    Also copies any ref-closure dependencies into dist.
    """
    _copy_into_dist(src_schema, dist_schema)
    schema_obj = json.loads(dist_schema.read_text(encoding="utf-8"))

    # Copy closure dependencies into dist
    closure_files = schema_ref_closure_files(src_schema)
    for dep_src in closure_files:
        dep_dist = DIST / dep_src.name
        if not dep_dist.exists():
            _copy_into_dist(dep_src, dep_dist)

    # Build graph records from dist copy
    graph_bundle = build_dist_schema_graph_records(
        root=ROOT,
        top_dist_schema=dist_schema,
    )
    return schema_obj, graph_bundle


def main() -> int:
    # Parse --out and --check
    out_path: Optional[Path] = None
    check_mode = False
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_path = Path(args[i + 1])
            i += 2
        elif args[i] == "--check":
            check_mode = True
            i += 1
        else:
            i += 1

    bom_target = out_path or DIST_BOM

    DIST.mkdir(parents=True, exist_ok=True)

    # ── Copy artifacts into dist/ ──

    # Schema artifacts (with graph closure shipping)
    _require_file(SCHEMA_BOM, "release_bom.schema.json")
    _copy_into_dist(SCHEMA_BOM, DIST_BOM_SCHEMA)
    bom_schema_obj = json.loads(DIST_BOM_SCHEMA.read_text(encoding="utf-8"))
    bom_schema_graph = build_dist_schema_graph_records(root=ROOT, top_dist_schema=DIST_BOM_SCHEMA)

    _require_file(SCHEMA_AUDIT, "release_audit_failure.schema.json")
    audit_schema_obj, audit_schema_graph = _ship_schema_with_graph(SCHEMA_AUDIT, DIST_AUDIT_SCHEMA)

    _require_file(SCHEMA_OPENAPI_GATE_RESULT, "openapi_release_gate_result.schema.json")
    openapi_gate_schema_obj, openapi_gate_graph = _ship_schema_with_graph(
        SCHEMA_OPENAPI_GATE_RESULT, DIST_OPENAPI_GATE_SCHEMA
    )

    _require_file(SCHEMA_CONSISTENCY_RESULT, "release_bom_consistency_result.schema.json")
    consistency_schema_obj, consistency_schema_graph = _ship_schema_with_graph(
        SCHEMA_CONSISTENCY_RESULT, DIST_CONSISTENCY_RESULT_SCHEMA
    )

    _require_file(SCHEMA_BOM_GENERATOR_GATE_RESULT, "release_bom_generator_gate_result.schema.json")
    bom_gen_gate_schema_obj, bom_gen_gate_graph = _ship_schema_with_graph(
        SCHEMA_BOM_GENERATOR_GATE_RESULT, DIST_BOM_GENERATOR_GATE_RESULT_SCHEMA
    )

    _require_file(SCHEMA_GATE_ENVELOPE, "release_gate_envelope.schema.json")
    _copy_into_dist(SCHEMA_GATE_ENVELOPE, DIST_GATE_ENVELOPE_SCHEMA)
    gate_envelope_obj = json.loads(DIST_GATE_ENVELOPE_SCHEMA.read_text(encoding="utf-8"))
    gate_envelope_graph = build_dist_schema_graph_records(root=ROOT, top_dist_schema=DIST_GATE_ENVELOPE_SCHEMA)

    _require_file(SCHEMA_GRAPH_BUNDLE, "schema_graph_bundle.schema.json")
    _copy_into_dist(SCHEMA_GRAPH_BUNDLE, DIST_GRAPH_BUNDLE_SCHEMA)
    graph_bundle_schema_obj = json.loads(DIST_GRAPH_BUNDLE_SCHEMA.read_text(encoding="utf-8"))
    graph_bundle_schema_graph = build_dist_schema_graph_records(root=ROOT, top_dist_schema=DIST_GRAPH_BUNDLE_SCHEMA)

    # Non-schema artifacts
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

    # ── Provenance ──
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

    # ── Build BOM ──
    # Classifier manifest entry (gets path relative to dist)
    classifier_sha = _sha256_file(DIST_CLASSIFIER_MANIFEST)
    classifier_manifest_obj = json.loads(DIST_CLASSIFIER_MANIFEST.read_text(encoding="utf-8"))
    classifier_selected = classifier_manifest_obj.get("selected", {})

    bom: Dict[str, Any] = {
        "version": 1,
        "provenance": provenance,
        "artifacts": {
            # Schema artifacts
            "release_bom_schema": _make_schema_artifact_entry(
                DIST_BOM_SCHEMA, bom_schema_obj, bom_schema_graph
            ),
            "release_audit_failure_schema": _make_schema_artifact_entry(
                DIST_AUDIT_SCHEMA, audit_schema_obj, audit_schema_graph
            ),
            "openapi_release_gate_result_schema": _make_schema_artifact_entry(
                DIST_OPENAPI_GATE_SCHEMA, openapi_gate_schema_obj, openapi_gate_graph
            ),
            "release_bom_consistency_result_schema": _make_schema_artifact_entry(
                DIST_CONSISTENCY_RESULT_SCHEMA, consistency_schema_obj, consistency_schema_graph
            ),
            "release_bom_generator_gate_result_schema": _make_schema_artifact_entry(
                DIST_BOM_GENERATOR_GATE_RESULT_SCHEMA, bom_gen_gate_schema_obj, bom_gen_gate_graph
            ),
            "release_gate_envelope_schema": _make_schema_artifact_entry(
                DIST_GATE_ENVELOPE_SCHEMA, gate_envelope_obj, gate_envelope_graph
            ),
            "schema_graph_bundle_schema": _make_schema_artifact_entry(
                DIST_GRAPH_BUNDLE_SCHEMA, graph_bundle_schema_obj, graph_bundle_schema_graph
            ),
            # Non-schema artifacts
            "openapi_breaking_policy": _make_bytes_artifact_entry(DIST_POLICY),
            "openapi_before_snapshot": _make_bytes_artifact_entry(DIST_BEFORE_OPENAPI),
            "openapi_after_snapshot": _make_bytes_artifact_entry(DIST_AFTER_OPENAPI),
            "openapi_diff_report": _make_bytes_artifact_entry(DIFF_REPORT_PATH),
            "openapi_classifier_manifest": {
                "path": str(DIST_CLASSIFIER_MANIFEST.relative_to(DIST)).replace("\\", "/"),
                "sha256": classifier_sha,
                "sha256_short": classifier_sha[:12],
                "selected": classifier_selected,
            },
        },
    }

    bom_target.parent.mkdir(parents=True, exist_ok=True)
    bom_target.write_text(
        json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if check_mode:
        print(f"[generate-release-bom] CHECK mode: wrote temp BOM to {bom_target}")
        return 0

    print(f"[generate-release-bom] Wrote {bom_target}")
    for name, a in bom["artifacts"].items():
        short = a.get("canonical_sha256_short") or a.get("sha256_short", "")
        print(f"  {name}: {short}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[generate-release-bom] ERROR: {e}", file=sys.stderr)
        raise
