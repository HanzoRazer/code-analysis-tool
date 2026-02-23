"""Refresh the BOM manifest file.

This script computes AST-semantic hashes for BOM-related scripts and
canonical JSON hashes for BOM-related schemas, writing results to
tests/contracts/bom_manifest.json.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "contracts" / "bom_manifest.json"

# Scripts whose AST hashes are tracked
TARGET_FILES = [
    ROOT / "scripts" / "generate_release_bom.py",
    ROOT / "scripts" / "check_release_bom_consistency.py",
]

# JSON schemas whose canonical hashes are tracked
JSON_TARGET_FILES = [
    ROOT / "schemas" / "release_bom.schema.json",
    ROOT / "schemas" / "release_audit_failure.schema.json",
]

# Import from the existing AST semantic hash helper
sys.path.insert(0, str(ROOT / "scripts"))
from ast_semantic_hash import semantic_hash_python_like_file  # type: ignore


# --- Version anchor ----------------------------------------------------------

_VERSION_KEYS = {"bom_logic_version"}


class _NeutralizeVersionLiterals(ast.NodeTransformer):
    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _VERSION_KEYS:
                node.value = ast.Constant(value="__NEUTRALIZED__")
                return node
        return self.generic_visit(node)


# --- Canonical JSON hashing --------------------------------------------------

def _canonical_json_sha256(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    canonical = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    # Script AST hashes
    file_entries: Dict[str, Dict[str, str]] = {}
    for f in TARGET_FILES:
        if not f.exists():
            print(f"[refresh-bom-manifest] WARNING: {f} not found, skipping.", file=sys.stderr)
            continue
        result = semantic_hash_python_like_file(f)
        rel = str(f.resolve().relative_to(ROOT))
        file_entries[rel] = {
            "sha256": result.sha256,
            "sha256_short": result.sha256[:12],
            "mode": result.mode,
        }

    # JSON schema canonical hashes
    json_entries: Dict[str, Dict[str, str]] = {}
    for f in JSON_TARGET_FILES:
        if not f.exists():
            print(f"[refresh-bom-manifest] WARNING: {f} not found, skipping.", file=sys.stderr)
            continue
        sha = _canonical_json_sha256(f)
        rel = str(f.resolve().relative_to(ROOT))
        json_entries[rel] = {
            "sha256": sha,
            "sha256_short": sha[:12],
        }

    manifest: Dict[str, Any] = {
        "version": 1,
        "files": file_entries,
        "json_files": json_entries,
    }

    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"[refresh-bom-manifest] Wrote {MANIFEST_PATH}")
    for k, v in sorted(file_entries.items()):
        print(f"  {k}: {v['sha256_short']} ({v['mode']})")
    for k, v in sorted(json_entries.items()):
        print(f"  {k}: {v['sha256_short']} (canonical-json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
