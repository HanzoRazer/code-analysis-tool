"""Contract gate: supported_rule_ids change requires signal_logic_version bump.

Uses ids-only hash (stricter variant):
  - Parses docs/rule_registry.json
  - Extracts supported_rule_ids only
  - Normalizes via sorted(set(...))
  - Hashes canonical JSON encoding

This means:
  - Reformatting JSON does NOT trigger the gate
  - Adding metadata fields does NOT trigger the gate
  - Only actual rule ID changes trigger the gate
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "rule_registry_manifest.json"
REGISTRY = ROOT / "docs" / "rule_registry.json"


def _hash_supported_rule_ids(path: Path) -> str:
    """Strict hash: only the normalized supported_rule_ids array."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    ids = obj.get("supported_rule_ids")

    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise AssertionError(
            "docs/rule_registry.json must contain supported_rule_ids: list[str]"
        )

    normalized = sorted(set(ids))
    canonical = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _current_signal_logic_version() -> str:
    """Read signal_logic_version from RunResult default."""
    from code_audit.model.run_result import RunResult

    return RunResult().signal_logic_version


@pytest.mark.contract
def test_rule_registry_change_requires_signal_logic_bump() -> None:
    """Public contract gate:

    If docs/rule_registry.json supported_rule_ids change,
    signal_logic_version must bump and the rule_registry_manifest
    must be refreshed.
    """
    assert MANIFEST.exists(), (
        f"Missing manifest: {MANIFEST}.\n"
        "Run: python scripts/refresh_rule_registry_manifest.py"
    )
    assert REGISTRY.exists(), (
        f"Missing registry: {REGISTRY}.\n"
        "Run: python scripts/sync_rule_registry.py --write"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    prev_signal_logic = manifest["signal_logic_version"]
    prev_hash = manifest["rule_registry_sha256"]

    current_hash = _hash_supported_rule_ids(REGISTRY)
    current_signal_logic = _current_signal_logic_version()

    if current_hash != prev_hash and current_signal_logic == prev_signal_logic:
        raise AssertionError(
            "supported_rule_ids changed but signal_logic_version was not "
            "bumped.\n"
            f"  previous signal_logic_version: {prev_signal_logic}\n"
            f"  current  signal_logic_version: {current_signal_logic}\n"
            f"  manifest hash: {prev_hash}\n"
            f"  current  hash: {current_hash}\n"
            "\nRequired steps:\n"
            "  1) Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
            "  2) Refresh manifest: python "
            "scripts/refresh_rule_registry_manifest.py\n"
        )

    # If signal_logic_version bumped, require manifest refresh.
    assert current_hash == prev_hash, (
        "rule_registry_manifest.json is stale.\n"
        f"  manifest hash: {prev_hash}\n"
        f"  current  hash: {current_hash}\n"
        "Fix: python scripts/refresh_rule_registry_manifest.py"
    )
