#!/usr/bin/env python3
"""Refresh tests/contracts/public_rule_registry_manifest.json.

Records:
  - signal_logic_version (current)
  - hash of normalized PUBLIC_RULE_IDS (canonical source)
  - hash of normalized docs/rule_registry.json supported_rule_ids (published)

The contract gate test_public_rules_registry_parity_contract.py compares
against this manifest to detect unversioned or inconsistent rule changes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from code_audit.model.run_result import RunResult
from code_audit.rules import PUBLIC_RULE_IDS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "contracts" / "public_rule_registry_manifest.json"
REGISTRY = ROOT / "docs" / "rule_registry.json"


def _hash_ids(ids: list[str]) -> str:
    """Canonical hash of a normalized rule ID list."""
    normalized = sorted(set(ids))
    canonical = json.dumps(
        normalized, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_docs_supported_ids(path: Path) -> str:
    """Extract and hash supported_rule_ids from docs/rule_registry.json."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    ids = obj.get("supported_rule_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise SystemExit(
            "docs/rule_registry.json must contain "
            "supported_rule_ids: list[str]"
        )
    return _hash_ids(ids)


def main() -> int:
    if not REGISTRY.exists():
        raise SystemExit(
            f"Missing {REGISTRY}. "
            "Generate it first: python scripts/sync_rule_registry.py --write"
        )

    payload = {
        "docs_supported_rule_ids_sha256": _hash_docs_supported_ids(REGISTRY),
        "hash_scope": "supported_rule_ids_only",
        "paths": {
            "canonical": "src/code_audit/rules.py:PUBLIC_RULE_IDS",
            "registry": "docs/rule_registry.json:supported_rule_ids",
        },
        "public_rule_ids_sha256": _hash_ids(PUBLIC_RULE_IDS),
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
