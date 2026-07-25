"""Refresh the BOM manifest file.

This script computes AST-semantic hashes for BOM-related scripts and
canonical JSON hashes for BOM-related schemas, writing results to
tests/contracts/bom_manifest.json.

AST dumps are interpreter-sensitive. Refresh **only** on the CI Python
(3.11). Running on 3.14 (or other versions) writes hashes that fail the
gate on CI — same class of defect as unpinned OpenAPI / confidence hashes.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "contracts" / "bom_manifest.json"

# Must match .github/workflows/pytest.yml matrix python-version.
_REQUIRED_PYTHON = (3, 11)

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
ast_semantic_hash = importlib.import_module("ast_semantic_hash")
semantic_hash_python_like_file = ast_semantic_hash.semantic_hash_python_like_file


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
    canonical = (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    )
    return hashlib.sha256(canonical).hexdigest()


def _require_ci_python() -> None:
    if sys.version_info[:2] != _REQUIRED_PYTHON:
        ver = ".".join(str(x) for x in sys.version_info[:3])
        req = ".".join(str(x) for x in _REQUIRED_PYTHON)
        raise SystemExit(
            f"[refresh-bom-manifest] Refusing to run on Python {ver}.\n"
            f"AST hashes must be generated with Python {req} (CI gate version).\n"
            f"Re-run: py -{req} scripts/refresh_bom_manifest.py\n"
            f"(or: python{req} scripts/refresh_bom_manifest.py)"
        )


def main() -> int:
    _require_ci_python()

    # Script AST hashes
    file_entries: dict[str, dict[str, str]] = {}
    for f in TARGET_FILES:
        if not f.exists():
            print(f"[refresh-bom-manifest] WARNING: {f} not found, skipping.", file=sys.stderr)
            continue
        result = semantic_hash_python_like_file(f)
        # Keep manifest paths stable across OSes so Windows refreshes do not break Linux CI.
        rel = f.resolve().relative_to(ROOT).as_posix()
        file_entries[rel] = {
            "sha256": result.sha256,
            "sha256_short": result.sha256[:12],
            "mode": result.mode,
        }

    # JSON schema canonical hashes
    json_entries: dict[str, dict[str, str]] = {}
    for f in JSON_TARGET_FILES:
        if not f.exists():
            print(f"[refresh-bom-manifest] WARNING: {f} not found, skipping.", file=sys.stderr)
            continue
        sha = _canonical_json_sha256(f)
        # Keep manifest paths stable across OSes so Windows refreshes do not break Linux CI.
        rel = f.resolve().relative_to(ROOT).as_posix()
        json_entries[rel] = {
            "sha256": sha,
            "sha256_short": sha[:12],
        }

    manifest: dict[str, Any] = {
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
