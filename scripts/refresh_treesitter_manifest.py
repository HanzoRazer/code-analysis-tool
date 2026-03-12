"""Refresh the tree-sitter manifest (governance gate).

Hashes all parser wrapper files and versions.json to detect
changes that require a signal_logic_version bump.

Usage::

    python scripts/refresh_treesitter_manifest.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PARSERS_DIR = REPO_ROOT / "src" / "code_audit" / "parsers"
VERSIONS_JSON = REPO_ROOT / "src" / "code_audit" / "contracts" / "versions.json"
QUERIES_DIR = REPO_ROOT / "src" / "code_audit" / "data" / "treesitter" / "queries"
OUT = REPO_ROOT / "tests" / "contracts" / "treesitter_manifest.json"


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def _find_signal_logic_version() -> str:
    """Read signal_logic_version from versions.json."""
    data = json.loads(VERSIONS_JSON.read_text(encoding="utf-8"))
    return data["signal_logic_version"]


def main() -> int:
    if not PARSERS_DIR.exists():
        print(f"error: parsers dir does not exist: {PARSERS_DIR}")
        return 1

    # Hash parser files
    files = sorted(PARSERS_DIR.glob("*.py"))
    mapping: dict[str, str] = {}
    for p in files:
        rel = p.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(p)

    # Hash query files if present
    if QUERIES_DIR.exists():
        for p in sorted(QUERIES_DIR.glob("*.scm")):
            rel = p.relative_to(REPO_ROOT).as_posix()
            mapping[rel] = _sha256_file(p)

    # Hash versions.json (version anchor governance)
    if VERSIONS_JSON.exists():
        rel = VERSIONS_JSON.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(VERSIONS_JSON)

    # Empty hash guard
    if not mapping:
        print("error: no parser files found — manifest would be empty")
        return 1

    payload = {
        "manifest_version": 1,
        "signal_logic_version": _find_signal_logic_version(),
        "versions_json_hash": _sha256_file(VERSIONS_JSON) if VERSIONS_JSON.exists() else "",
        "files": mapping,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(mapping)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
