#!/usr/bin/env python3
"""Refresh the OpenAPI scrub baseline manifest.

Records the SHA-256 hash of the scrub audit baseline file alongside
the current ``signal_logic_version``.  The contract test
``test_openapi_scrub_baseline_requires_signal_logic_bump`` compares
these values to detect ungoverned changes.

Usage:
  python scripts/refresh_openapi_scrub_baseline_manifest.py
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "contracts" / "openapi_scrub_audit_baseline.json"
OUT = ROOT / "tests" / "contracts" / "openapi_scrub_baseline_manifest.json"


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


def validate_baseline_shape() -> None:
    """Lightweight structural validation so you don't hash garbage."""
    if not BASELINE.exists():
        raise SystemExit(f"Missing baseline: {BASELINE}")
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise SystemExit("Baseline version must be 1")
    if not isinstance(data.get("accepted_json_paths", []), list):
        raise SystemExit("accepted_json_paths must be a list")
    if not isinstance(data.get("accepted_keys", []), list):
        raise SystemExit("accepted_keys must be a list")


def main() -> int:
    validate_baseline_shape()
    manifest = {
        "manifest_version": 1,
        "signal_logic_version": read_signal_logic_version(),
        "baseline_path": BASELINE.relative_to(ROOT).as_posix(),
        "baseline_sha256": sha256_file(BASELINE),
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
