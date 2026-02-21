#!/usr/bin/env python3
"""Refresh the OpenAPI scrub budgets manifest.

Records the SHA-256 hash of the budgets policy file alongside the
current ``signal_logic_version``.  The contract test
``test_openapi_scrub_budgets_requires_signal_logic_bump`` compares
these values to detect ungoverned changes.

Usage:
  python scripts/refresh_openapi_scrub_budgets_manifest.py
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUDGETS = ROOT / "tests" / "contracts" / "openapi_scrub_budgets.json"
OUT = ROOT / "tests" / "contracts" / "openapi_scrub_budgets_manifest.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_signal_logic_version() -> str:
    target = ROOT / "src" / "code_audit" / "model" / "run_result.py"
    txt = target.read_text(encoding="utf-8")
    m = re.search(r'\bsignal_logic_version(?:\s*:\s*\S+)?\s*=\s*"([^"]+)"', txt)
    if not m:
        raise SystemExit(
            "Could not locate signal_logic_version in "
            "src/code_audit/model/run_result.py"
        )
    return m.group(1)


def validate_budgets_shape() -> None:
    """Lightweight structural validation before hashing."""
    if not BUDGETS.exists():
        raise SystemExit(f"Missing budgets file: {BUDGETS}")
    data = json.loads(BUDGETS.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise SystemExit("Budgets file version must be 1")
    default = data.get("default")
    if not isinstance(default, dict):
        raise SystemExit("Budgets file must contain object: default")
    if "max_removed_fields" not in default:
        raise SystemExit("Budgets default must include max_removed_fields")
    endpoints = data.get("endpoints")
    if endpoints is None:
        raise SystemExit(
            "Budgets file must include endpoints object (can be empty)"
        )
    if not isinstance(endpoints, dict):
        raise SystemExit(
            "Budgets endpoints must be an object mapping "
            "'METHOD /path' -> budget object"
        )


def main() -> int:
    validate_budgets_shape()

    manifest = {
        "manifest_version": 1,
        "signal_logic_version": read_signal_logic_version(),
        "budgets_path": BUDGETS.relative_to(ROOT).as_posix(),
        "budgets_sha256": sha256_file(BUDGETS),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
