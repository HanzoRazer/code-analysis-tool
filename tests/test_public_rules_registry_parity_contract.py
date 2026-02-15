"""Contract gate: PUBLIC_RULE_IDS <-> docs/rule_registry.json parity.

Reverse-direction enforcement:
  - PUBLIC_RULE_IDS is canonical.
  - docs/rule_registry.json must be regenerated to match it.
  - Any semantic change requires a signal_logic_version bump + manifest refresh.

Uses ids-only hash (normalized: sorted, unique, canonical JSON encoding)
so formatting/metadata changes do NOT trigger the gate.

Change type               | Triggers gate?
--------------------------|---------------
Reformat JSON             | No
Add metadata field        | No
Reorder IDs               | No (normalized)
Add/remove rule ID        | Yes
Rename rule ID            | Yes
Hand-edit docs registry   | Yes (must come from PUBLIC_RULE_IDS)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from code_audit.model.run_result import RunResult
from code_audit.rules import PUBLIC_RULE_IDS

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "contracts" / "public_rule_registry_manifest.json"
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
        raise AssertionError(
            "docs/rule_registry.json must contain supported_rule_ids: list[str]"
        )
    return _hash_ids(ids)


@pytest.mark.contract
def test_public_rule_ids_change_requires_registry_regen_and_signal_bump() -> (
    None
):
    """Reverse-direction enforcement:

    - PUBLIC_RULE_IDS is canonical.
    - docs/rule_registry.json must be regenerated to match it.
    - Any semantic change requires signal_logic_version bump + manifest refresh.
    """
    assert MANIFEST.exists(), (
        f"Missing manifest: {MANIFEST}.\n"
        "Run: python scripts/refresh_public_rule_registry_manifest.py"
    )
    assert REGISTRY.exists(), (
        f"Missing registry: {REGISTRY}.\n"
        "Run: python scripts/sync_rule_registry.py --write"
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    prev_signal_logic = manifest["signal_logic_version"]
    prev_public_hash = manifest["public_rule_ids_sha256"]
    prev_docs_hash = manifest["docs_supported_rule_ids_sha256"]

    current_public_hash = _hash_ids(PUBLIC_RULE_IDS)
    current_docs_hash = _hash_docs_supported_ids(REGISTRY)
    current_signal_logic = RunResult().signal_logic_version

    # 1) Canonical changed but docs not regenerated.
    if (
        current_public_hash != prev_public_hash
        and current_docs_hash == prev_docs_hash
    ):
        raise AssertionError(
            "PUBLIC_RULE_IDS changed but docs/rule_registry.json was not "
            "regenerated.\n"
            f"  previous PUBLIC hash: {prev_public_hash}\n"
            f"  current  PUBLIC hash: {current_public_hash}\n"
            f"  docs hash unchanged:  {current_docs_hash}\n"
            "\nFix:\n"
            "  python scripts/sync_rule_registry.py --write\n"
            "  python scripts/refresh_public_rule_registry_manifest.py\n"
        )

    # 2) Docs changed but canonical did not (hand-edit).
    if (
        current_public_hash == prev_public_hash
        and current_docs_hash != prev_docs_hash
    ):
        raise AssertionError(
            "docs/rule_registry.json changed but PUBLIC_RULE_IDS did not.\n"
            "Do not hand-edit the registry; regenerate from PUBLIC_RULE_IDS.\n"
            "\nFix:\n"
            "  python scripts/sync_rule_registry.py --write\n"
            "  python scripts/refresh_public_rule_registry_manifest.py\n"
        )

    # 3) Semantic change without signal_logic_version bump.
    if (
        current_public_hash != prev_public_hash
        or current_docs_hash != prev_docs_hash
    ) and current_signal_logic == prev_signal_logic:
        raise AssertionError(
            "Public rule surface changed but signal_logic_version was not "
            "bumped.\n"
            f"  previous signal_logic_version: {prev_signal_logic}\n"
            f"  current  signal_logic_version: {current_signal_logic}\n"
            "\nRequired steps:\n"
            "  1) Bump signal_logic_version in "
            "src/code_audit/model/run_result.py\n"
            "  2) Regenerate: python scripts/sync_rule_registry.py --write\n"
            "  3) Refresh: python "
            "scripts/refresh_public_rule_registry_manifest.py\n"
        )

    # 4) Final equality — manifest must be current.
    assert current_public_hash == prev_public_hash, (
        "public_rule_registry_manifest.json is stale "
        "(PUBLIC_RULE_IDS hash mismatch).\n"
        f"  manifest: {prev_public_hash}\n"
        f"  current:  {current_public_hash}\n"
        "Fix: python scripts/refresh_public_rule_registry_manifest.py"
    )
    assert current_docs_hash == prev_docs_hash, (
        "public_rule_registry_manifest.json is stale "
        "(docs supported_rule_ids hash mismatch).\n"
        f"  manifest: {prev_docs_hash}\n"
        f"  current:  {current_docs_hash}\n"
        "Fix: python scripts/refresh_public_rule_registry_manifest.py"
    )
