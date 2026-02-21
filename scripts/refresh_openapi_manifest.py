#!/usr/bin/env python3
"""Refresh the OpenAPI manifest: tests/contracts/openapi_manifest.json.

Records ``signal_logic_version`` + SHA-256 of ``docs/openapi.json`` so the
gate test can detect OpenAPI surface changes that weren't accompanied by a
``signal_logic_version`` bump.

Usage:
  python scripts/refresh_openapi_manifest.py
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = REPO_ROOT / "docs" / "openapi.json"
OUT = REPO_ROOT / "tests" / "contracts" / "openapi_manifest.json"
SRC = REPO_ROOT / "src"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        SRC / "code_audit" / "model" / "run_result.py",
        SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise SystemExit("error: could not locate signal_logic_version default")


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def main() -> int:
    if not SNAPSHOT.exists():
        raise SystemExit(
            f"Missing OpenAPI snapshot: {SNAPSHOT}\n"
            "Generate it with:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "openapi_snapshot_sha256": _sha256_file(SNAPSHOT),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
