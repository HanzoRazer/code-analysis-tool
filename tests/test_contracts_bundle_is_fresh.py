"""Contract gate: docs/contracts_bundle.json must exist and be valid.

The contracts bundle is a single manifest containing SHA-256 hashes of all
contract artifacts consumed by downstream repos. Downstream CI can fetch
this one file and verify parity without downloading every artifact.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "docs" / "contracts_bundle.json"


@pytest.mark.contract
def test_contracts_bundle_is_present_and_valid_json() -> None:
    """docs/contracts_bundle.json must exist and have valid structure."""
    assert BUNDLE.exists(), (
        "Missing docs/contracts_bundle.json.\n"
        "Run: python scripts/refresh_contracts_bundle.py"
    )
    obj = json.loads(BUNDLE.read_text(encoding="utf-8"))
    assert "artifacts" in obj and isinstance(obj["artifacts"], dict), (
        "contracts_bundle.json missing 'artifacts' dict"
    )
    for name, meta in obj["artifacts"].items():
        assert "path" in meta, f"artifact {name!r} missing 'path'"
        assert "sha256" in meta, f"artifact {name!r} missing 'sha256'"
        assert "hash_scope" in meta, f"artifact {name!r} missing 'hash_scope'"


@pytest.mark.contract
def test_contracts_bundle_hashes_are_current() -> None:
    """Bundle hashes must match the actual artifact files on disk."""
    assert BUNDLE.exists(), (
        "Missing docs/contracts_bundle.json.\n"
        "Run: python scripts/refresh_contracts_bundle.py"
    )
    obj = json.loads(BUNDLE.read_text(encoding="utf-8"))
    artifacts = obj.get("artifacts", {})

    stale: list[str] = []
    for name, meta in artifacts.items():
        p = ROOT / meta["path"]
        if not p.exists():
            stale.append(f"{name}: file missing ({meta['path']})")
            continue

        scope = meta["hash_scope"]
        expected = meta["sha256"]

        if scope == "file_bytes":
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
        elif scope == "supported_rule_ids_only":
            reg = json.loads(p.read_text(encoding="utf-8"))
            ids = sorted(set(reg.get("supported_rule_ids", [])))
            canonical = json.dumps(
                ids, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            actual = hashlib.sha256(canonical).hexdigest()
        else:
            stale.append(f"{name}: unknown hash_scope {scope!r}")
            continue

        if actual != expected:
            stale.append(
                f"{name}: hash mismatch\n"
                f"    expected: {expected}\n"
                f"    actual:   {actual}"
            )

    assert not stale, (
        "contracts_bundle.json is stale:\n  - "
        + "\n  - ".join(stale)
        + "\nFix: python scripts/refresh_contracts_bundle.py"
    )
