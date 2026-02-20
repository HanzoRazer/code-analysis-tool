#!/usr/bin/env python3
"""Hash a controlled subset of pyproject.toml keys.

Extracts only an explicitly whitelisted set of keys from pyproject.toml,
serializes them into canonical JSON (sorted keys, compact separators),
and computes a SHA-256 hash.  This ensures:

  - Formatting/comment changes to pyproject.toml don't count as drift.
  - Only semantically meaningful keys (for confidence scoring) are governed.
  - The hash is deterministic across platforms and Python versions.

Usage (standalone):
    python scripts/toml_subset_hash.py

Programmatic:
    from scripts.toml_subset_hash import canonical_toml_subset_hash
    h, subset = canonical_toml_subset_hash(path, [["tool", "code_audit", "confidence"]])
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import tomllib


def _get_path(obj: dict[str, Any], path: list[str]) -> Any:
    """Walk a nested dict by path segments, returning None if missing."""
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def canonical_toml_subset_hash(
    pyproject_path: Path,
    allowed_paths: list[list[str]],
) -> tuple[str, dict[str, Any]]:
    """Read pyproject.toml and hash only the explicitly allowed paths.

    Returns (sha256, extracted_subset_dict).

    Missing keys are represented as ``null`` in the subset dict for stability —
    adding a previously-absent key is still a governed change.
    """
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    subset: dict[str, Any] = {}
    for p in allowed_paths:
        val = _get_path(data, p)
        # Represent missing as null explicitly for stability
        key = ".".join(p)
        subset[key] = val

    # Canonical JSON representation (sorted keys) ensures stable hashing
    blob = json.dumps(
        subset,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    h = hashlib.sha256(blob).hexdigest()
    return h, subset


def main() -> int:
    """Print the canonical subset hash for the repo's pyproject.toml."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    allowed = [["tool", "code_audit", "confidence"]]
    h, subset = canonical_toml_subset_hash(pyproject, allowed)
    print(f"sha256: {h}")
    print(f"subset: {json.dumps(subset, indent=2)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
