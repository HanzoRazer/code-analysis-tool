from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from ast_semantic_hash import semantic_hash_python_like_file  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "contracts" / "bom_manifest.json"


def _load_manifest() -> dict:
    assert MANIFEST_PATH.exists(), f"Missing {MANIFEST_PATH}"
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _canonical_json_sha256(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    canonical = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"
    return hashlib.sha256(canonical).hexdigest()


def test_bom_manifest_script_ast_hashes_match() -> None:
    """
    Every script listed in the BOM manifest 'files' section must have
    an AST hash matching the recorded value.
    If this fails, run: python scripts/refresh_bom_manifest.py
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
        assert p.exists(), f"BOM file missing: {rel_path}"
        result = semantic_hash_python_like_file(p)
        assert result.sha256 == expected_sha, (
            f"AST hash mismatch for {rel_path}: "
            f"expected {expected_sha}, got {result.sha256}. "
            "Run: python scripts/refresh_bom_manifest.py"
        )


def test_bom_manifest_json_schema_hashes_match() -> None:
    """
    Every JSON schema listed in 'json_files' must have a canonical JSON
    hash matching the manifest.
    If this fails, run: python scripts/refresh_bom_manifest.py
    """
    manifest = _load_manifest()
    json_files = manifest.get("json_files", {})
    if not json_files:
        return

    for rel_path, entry in sorted(json_files.items()):
        if entry == "REPLACE_ME":
            continue
        expected_sha = entry["sha256"] if isinstance(entry, dict) else entry
        p = ROOT / rel_path
        assert p.exists(), f"JSON file missing: {rel_path}"
        actual_hash = _canonical_json_sha256(p)
        assert actual_hash == expected_sha, (
            f"Canonical JSON hash mismatch for {rel_path}: "
            f"expected {expected_sha}, got {actual_hash}. "
            "Run: python scripts/refresh_bom_manifest.py"
        )
