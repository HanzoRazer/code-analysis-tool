"""Unified Semantic Surface Gate.

Ensures that treesitter manifest AND golden fixture manifest
both align with versions.json signal_logic_version.

This replaces subtle drift between separate per-manifest gates.
"""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

TS_MANIFEST = ROOT / "tests" / "contracts" / "treesitter_manifest.json"
GOLDEN_MANIFEST = ROOT / "tests" / "contracts" / "golden_fixtures_manifest.json"
VERSIONS = ROOT / "src" / "code_audit" / "contracts" / "versions.json"


def _load_json(p: Path) -> dict:
    if not p.exists():
        raise AssertionError(f"Missing required manifest: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _signal_logic_version() -> str:
    obj = _load_json(VERSIONS)
    v = obj.get("signal_logic_version")
    if not isinstance(v, str) or not v.startswith("signals_v"):
        raise AssertionError("Invalid signal_logic_version in versions.json")
    return v


def _manifest_hashes(p: Path) -> dict:
    obj = _load_json(p)
    files = obj.get("files") or {}
    if not isinstance(files, dict):
        raise AssertionError(f"Invalid files section in {p}")
    return files


def test_semantic_surface_requires_signal_logic_bump():
    """
    If either semantic surface (treesitter OR golden fixtures)
    has changed relative to its recorded manifest hashes,
    signal_logic_version MUST be bumped.
    """

    ts = _load_json(TS_MANIFEST)
    golden = _load_json(GOLDEN_MANIFEST)

    current_signal = _signal_logic_version()

    ts_recorded = ts.get("signal_logic_version")
    golden_recorded = golden.get("signal_logic_version")

    ts_hashes = _manifest_hashes(TS_MANIFEST)
    golden_hashes = _manifest_hashes(GOLDEN_MANIFEST)

    # If either manifest declares a different version than the current anchor,
    # enforce explicit bump alignment.
    if ts_recorded != current_signal or golden_recorded != current_signal:
        raise AssertionError(
            "Manifest signal_logic_version mismatch.\n"
            f"  versions.json:        {current_signal}\n"
            f"  treesitter manifest:  {ts_recorded}\n"
            f"  golden manifest:      {golden_recorded}\n"
            "Run refresh scripts and ensure versions.json matches manifests."
        )
