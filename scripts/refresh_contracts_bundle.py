#!/usr/bin/env python3
"""Refresh docs/contracts_bundle.json.

Generates a single manifest containing SHA-256 hashes of all contract
artifacts consumed by downstream repos (e.g., code-rescue-tool).

Downstream consumers can fetch this one file, compare hashes against
their vendored copies, and detect drift without downloading every artifact.

Usage:
    python scripts/refresh_contracts_bundle.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "contracts_bundle.json"

# Contract artifacts consumed by downstream repos.
# key → repo-relative path
ARTIFACTS: dict[str, str] = {
    "run_result_schema": "schemas/run_result.schema.json",
    "rule_registry": "docs/rule_registry.json",
    "rule_registry_schema": "schemas/rule_registry.schema.json",
}


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _hash_supported_rule_ids_only(path: Path) -> str:
    """Hash only the sorted, deduplicated supported_rule_ids list."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    ids = obj.get("supported_rule_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise SystemExit(
            "docs/rule_registry.json must contain supported_rule_ids: list[str]"
        )
    normalized = sorted(set(ids))
    canonical = json.dumps(
        normalized, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_bytes(canonical)


def main() -> int:
    from code_audit.model.run_result import RunResult

    signal_logic_version = RunResult().signal_logic_version

    hashes: dict[str, dict[str, str]] = {}
    for key, rel in ARTIFACTS.items():
        p = ROOT / rel
        if not p.exists():
            raise SystemExit(f"Missing required contract artifact: {rel}")
        if key == "rule_registry":
            hashes[key] = {
                "hash_scope": "supported_rule_ids_only",
                "path": rel,
                "sha256": _hash_supported_rule_ids_only(p),
            }
        else:
            hashes[key] = {
                "hash_scope": "file_bytes",
                "path": rel,
                "sha256": _sha256_file(p),
            }

    bundle = {
        "artifacts": hashes,
        "signal_logic_version": signal_logic_version,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"✓ Wrote {OUT.relative_to(ROOT)}")
    for key, meta in hashes.items():
        print(f"  {key}: {meta['sha256'][:16]}… ({meta['hash_scope']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
