from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from ast_semantic_hash import semantic_hash_python_like_file  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "contracts" / "openapi_classifier_manifest.json"


def _load_manifest() -> dict:
    assert MANIFEST_PATH.exists(), f"Missing {MANIFEST_PATH}"
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_openapi_classifier_manifest_closure_hashes_match() -> None:
    """
    Every file in the classifier closure must have an AST hash matching the manifest.
    If this test fails, run: python scripts/refresh_openapi_classifier_manifest.py
    """
    manifest = _load_manifest()
    cg = manifest.get("closure_graph", {})
    closure_files = cg.get("files", {})
    if not closure_files:
        return  # nothing to check yet

    for rel_path, entry in sorted(closure_files.items()):
        expected_sha = entry["sha256"] if isinstance(entry, dict) else entry
        p = ROOT / rel_path
        assert p.exists(), f"Closure file missing: {rel_path}"
        result = semantic_hash_python_like_file(p)
        assert result.sha256 == expected_sha, (
            f"AST hash mismatch for {rel_path}: "
            f"expected {expected_sha}, got {result.sha256}. "
            "Run: python scripts/refresh_openapi_classifier_manifest.py"
        )


def test_openapi_classifier_manifest_edge_graph_hash_matches() -> None:
    """
    The edge graph SHA must match the canonical serialization of the edges dict.
    """
    manifest = _load_manifest()
    cg = manifest.get("closure_graph", {})
    expected_sha = cg.get("edge_graph_sha256")
    if expected_sha == "REPLACE_ME" or not expected_sha:
        return  # not yet populated

    # Edges are stored at the top-level "edges" key as a dict
    edges = manifest.get("edges", {})
    # Convert to sorted list of [from, to] pairs for canonical hashing
    edge_list = []
    for src, dsts in sorted(edges.items()):
        for dst in sorted(dsts):
            edge_list.append([src, dst])

    canonical = json.dumps(edge_list, separators=(",", ":"), sort_keys=True).encode("utf-8")
    actual_sha = hashlib.sha256(canonical).hexdigest()
    assert actual_sha == expected_sha, (
        f"Edge graph hash mismatch: expected {expected_sha}, got {actual_sha}. "
        "Run: python scripts/refresh_openapi_classifier_manifest.py"
    )


def test_openapi_classifier_manifest_files_hashes_match() -> None:
    """
    The 'files' section hashes (entrypoint files) must match AST hashes.
    """
    manifest = _load_manifest()
    files = manifest.get("files", {})
    if not files:
        return

    for rel_path, entry in sorted(files.items()):
        if entry == "REPLACE_ME":
            continue
        expected_sha = entry["sha256"] if isinstance(entry, dict) else entry
        p = ROOT / rel_path
        assert p.exists(), f"File missing: {rel_path}"
        result = semantic_hash_python_like_file(p)
        assert result.sha256 == expected_sha, (
            f"AST hash mismatch for {rel_path}: "
            f"expected {expected_sha}, got {result.sha256}. "
            "Run: python scripts/refresh_openapi_classifier_manifest.py"
        )
