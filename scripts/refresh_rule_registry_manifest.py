#!/usr/bin/env python3
"""Refresh tests/contracts/rule_registry_manifest.json.

Stores:
  - signal_logic_version (current)
  - rule_registry_sha256 (ids-only hash of docs/rule_registry.json)

The contract gate test_rule_registry_requires_signal_logic_bump.py
compares against this manifest to detect unversioned rule changes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from code_audit.model.run_result import RunResult

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "contracts" / "rule_registry_manifest.json"
REGISTRY = ROOT / "docs" / "rule_registry.json"


def _hash_supported_rule_ids(path: Path) -> str:
    """Hash only the normalized supported_rule_ids array."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    ids = obj.get("supported_rule_ids")

    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise SystemExit(
            "docs/rule_registry.json must contain supported_rule_ids: list[str]"
        )

    normalized = sorted(set(ids))
    canonical = json.dumps(
        normalized, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def main() -> int:
    if not REGISTRY.exists():
        raise SystemExit(
            f"Missing {REGISTRY}. "
            "Generate it first: python scripts/sync_rule_registry.py --write"
        )

    payload = {
        "hash_scope": "supported_rule_ids_only",
        "path": "docs/rule_registry.json",
        "rule_registry_sha256": _hash_supported_rule_ids(REGISTRY),
        "signal_logic_version": RunResult().signal_logic_version,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
